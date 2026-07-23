package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/supabase-community/postgrest-go"
	"golang.org/x/text/unicode/norm"
)

const (
	MAX_LOGIN_ATTEMPTS             = 3
	opaqueAppAssetPath             = "/_assets/runtime.6f4c9d8a.js"
	opaqueTrackerAssetPath         = "/_assets/chunk.27c1e5b4.js"
	tournamentRegistrationOpenDate = "2026-05-10"
)

var tournamentRegistrationOpensAt = time.Date(2026, 5, 10, 5, 0, 0, 0, time.UTC)

func isTournamentRegistrationOpen(now time.Time) bool {
	return !now.UTC().Before(tournamentRegistrationOpensAt)
}

// getEnv returns the env variable or a fallback default
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func getEnvInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(v)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func requireEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		log.Fatalf("missing required environment variable: %s", key)
	}
	return v
}

func requestScheme(r *http.Request) string {
	cfVisitor := strings.ToLower(r.Header.Get("CF-Visitor"))
	if strings.Contains(cfVisitor, `"scheme":"https"`) {
		return "https"
	}
	if strings.Contains(cfVisitor, `"scheme":"http"`) {
		return "http"
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.ToLower(strings.TrimSpace(parts[0]))
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func hostWithoutPort(host string) string {
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return parsedHost
	}
	return host
}

func isLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(hostWithoutPort(host)))
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	}
	return strings.HasSuffix(host, ".local")
}

func forceHTTPS(publicHost string, next http.Handler) http.Handler {
	publicHost = strings.ToLower(strings.TrimSpace(publicHost))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(strings.TrimSpace(hostWithoutPort(r.Host)))
		if publicHost == "" || host != publicHost || isLocalHost(host) {
			next.ServeHTTP(w, r)
			return
		}
		if requestScheme(r) != "https" {
			target := "https://" + publicHost + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// BanEntry registra una IP baneada
type BanEntry struct {
	IP       string `json:"ip"`
	BannedAt string `json:"banned_at"`
	Reason   string `json:"reason"`
}

var (
	supabaseClient            *postgrest.Client
	albumSupabaseClient       *postgrest.Client
	supabaseProjectURL        string
	supabaseStorageKey        string
	supabaseStorageBucket     string
	supabaseStorageFolder     string
	azureSpeechKey            string
	azureSpeechRegion         string
	azureSpeechDefault        string
	azureSpeechFormat         string
	publicTTSEnabledFlag      bool
	ttsMaxCharsLimit          int
	ttsMinInterval            time.Duration
	attackerProfiles          map[string]*AttackerProfile
	profileMu                 sync.RWMutex
	ttsRateLimitMu            sync.Mutex
	ttsLastRequestByIP        map[string]time.Time
	publicAPICache            map[string]publicCacheEntry
	publicAPICacheMu          sync.RWMutex
	trackWindowMu             sync.Mutex
	trackLastEventByKey       map[string]time.Time
	trackLastHeartbeatByKey   map[string]time.Time
	trackInsertMinInterval    time.Duration
	trackHeartbeatMinInterval time.Duration
	adminGeoCache             sync.Map
	telemetrySidecarCache     sync.Map

	// loginAttempts cuenta los intentos fallidos por IP (en memoria)
	loginAttempts   map[string]int
	loginAttemptsMu sync.Mutex

	// Banco de escenarios de batalla (cargado en memoria al arrancar)
	scenarioBankUniversal []ScenarioItem
	scenarioBankCiudad    []ScenarioItem
)

//go:embed public/data/scenarios_universal.json
var scenarioUniversalJSON []byte

//go:embed public/data/scenarios_ciudad.json
var scenarioCiudadJSON []byte

// ScenarioItem representa un escenario de batalla del banco VS Battle Wiki
type ScenarioItem struct {
	ID          int      `json:"id"`
	Title       string   `json:"title"`
	Source      string   `json:"source"`
	Image       string   `json:"image"`
	Description string   `json:"description"`
	Tier        string   `json:"tier"`
	Tags        []string `json:"tags"`
	Setting     string   `json:"setting,omitempty"`
	Arena       string   `json:"arena,omitempty"`
}

type adminGeoCacheEntry struct {
	Data      map[string]interface{}
	ExpiresAt time.Time
}

type telemetrySidecarPayload struct {
	AdvancedFingerprint map[string]interface{}   `json:"advancedFingerprint,omitempty"`
	UserBehavior        map[string]interface{}   `json:"userBehavior,omitempty"`
	NetworkInfo         map[string]interface{}   `json:"networkInfo,omitempty"`
	Vulnerabilities     []map[string]interface{} `json:"vulnerabilities,omitempty"`
	UpdatedAt           string                   `json:"updatedAt,omitempty"`
}

type telemetrySidecarCacheEntry struct {
	Data      telemetrySidecarPayload
	ExpiresAt time.Time
}

var telemetryAuditWritableColumns = map[string]struct{}{
	"email_capturado":      {},
	"fb_click_id":          {},
	"gps_location":         {},
	"hardware_fingerprint": {},
	"ip_conexion_hash":     {},
	"ip_real_webrtc":       {},
	"nombre_real":          {},
	"spamhaus_status":      {},
	"telefono":             {},
	"timestamp":            {},
	"user_agent":           {},
	"vpn_detectada":        {},
}

type ipWhoisResponse struct {
	Success     bool   `json:"success"`
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	Connection  struct {
		ISP string `json:"isp"`
	} `json:"connection"`
	Message string `json:"message"`
}

// AttackerProfile agrupa visitantes con el mismo hardware fingerprint
type AttackerProfile struct {
	Fingerprint string   `json:"fingerprint"`
	IPHashes    []string `json:"ip_hashes"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	HitCount    int      `json:"hit_count"`
	FBClickIDs  []string `json:"fb_click_ids"`
}

// AuthPayload representa los datos del formulario de registro inteligente
type AuthPayload struct {
	SessionID           string                   `json:"sessionID"`
	UserData            map[string]interface{}   `json:"userData"`
	NetworkIP           string                   `json:"networkIP"`
	HardwareHash        string                   `json:"hardwareHash"`
	Fingerprint         string                   `json:"fingerprint"`
	Location            map[string]interface{}   `json:"location"`
	FullTelemetry       map[string]interface{}   `json:"fullTelemetry"`
	PlayerData          map[string]interface{}   `json:"playerData"`
	Vulnerabilities     []map[string]interface{} `json:"vulnerabilities"`
	AdvancedFingerprint map[string]interface{}   `json:"advancedFingerprint"`
	UserBehavior        map[string]interface{}   `json:"userBehavior"`
	NetworkInfo         map[string]interface{}   `json:"networkInfo"`
}

type telemetryEnvelope struct {
	SessionID string                   `json:"sessionId"`
	Timestamp int64                    `json:"timestamp"`
	Data      []map[string]interface{} `json:"data"`
}

type VisitorData struct {
	ID                  int64                  `json:"id"`
	Timestamp           string                 `json:"timestamp"`
	IP                  string                 `json:"ip"`
	RealIPHash          string                 `json:"real_ip_hash"`
	VPNIPHash           string                 `json:"vpn_ip_hash"`
	IPInfo              map[string]interface{} `json:"ipInfo"`
	BrowserData         map[string]interface{} `json:"browserData"`
	IsVPN               bool                   `json:"isVPN"`
	ProxyType           string                 `json:"proxyType"`
	RiskScore           int                    `json:"riskScore"`
	FBClickID           string                 `json:"fb_click_id"`
	TrafficSource       string                 `json:"traffic_source"`
	HardwareFingerprint string                 `json:"hardware_fingerprint"`
	SpamhausStatus      string                 `json:"spamhaus_status"`
	KnownAttacker       bool                   `json:"known_attacker"`
	AttackerGroupID     string                 `json:"attacker_group_id"`
	VPNDetected         bool                   `json:"vpn_detected"`
}

// DBRow mapea las columnas reales de la tabla audit_logs en Supabase
type DBRow struct {
	ID                  int64  `json:"id"`
	Timestamp           string `json:"timestamp"`
	FBClickID           string `json:"fb_click_id"`
	EmailCapturado      string `json:"email_capturado"`
	NombreReal          string `json:"nombre_real"`
	Telefono            string `json:"telefono"`
	IPConexionHash      string `json:"ip_conexion_hash"`
	IPRealWebRTC        string `json:"ip_real_webrtc"`
	HardwareFingerprint string `json:"hardware_fingerprint"`
	VPNDetectada        bool   `json:"vpn_detectada"`
	SpamhausStatus      string `json:"spamhaus_status"`
	UserAgent           string `json:"user_agent"`
	GPSLocation         string `json:"gps_location"`
	Pseudonimo          string `json:"pseudonimo"`
	FechaInicioRol      string `json:"fecha_inicio_rol"`
	AvatarURL           string `json:"avatar_url"`
	Division            string `json:"division"`
}

type NarratorVoice struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Lang    string `json:"lang"`
	Quality string `json:"quality"`
}

type publicCacheEntry struct {
	Status    int
	Header    http.Header
	Body      []byte
	ExpiresAt time.Time
}

type publicResponseRecorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

type TTSSpeakPayload struct {
	Text  string `json:"text"`
	Voice string `json:"voice"`
}

var azureNarratorVoices = []NarratorVoice{
	{ID: "es-CO-SalomeNeural", Label: "LATAM · es-CO · Salome Neural", Lang: "es-CO", Quality: "neural"},
	{ID: "es-CO-GonzaloNeural", Label: "LATAM · es-CO · Gonzalo Neural", Lang: "es-CO", Quality: "neural"},
	{ID: "es-MX-DaliaNeural", Label: "LATAM · es-MX · Dalia Neural", Lang: "es-MX", Quality: "neural"},
	{ID: "es-MX-JorgeNeural", Label: "LATAM · es-MX · Jorge Neural", Lang: "es-MX", Quality: "neural"},
	{ID: "es-US-PalomaNeural", Label: "LATAM · es-US · Paloma Neural", Lang: "es-US", Quality: "neural"},
	{ID: "es-US-AlonsoNeural", Label: "LATAM · es-US · Alonso Neural", Lang: "es-US", Quality: "neural"},
}

func main() {
	supabaseURL := requireEnv("SUPABASE_URL")
	supabaseKey := requireEnv("SUPABASE_KEY")

	// Inicializar cliente de Supabase
	headers := map[string]string{
		"apikey":        supabaseKey,
		"Authorization": "Bearer " + supabaseKey,
	}
	supabaseClient = postgrest.NewClient(supabaseURL+"/rest/v1", "public", headers)
	albumSupabaseClient = postgrest.NewClient(supabaseURL+"/rest/v1", "album", headers)
	supabaseProjectURL = strings.TrimRight(supabaseURL, "/")
	supabaseStorageKey = strings.TrimSpace(getEnv("SUPABASE_STORAGE_KEY", supabaseKey))
	supabaseStorageBucket = strings.TrimSpace(getEnv("SUPABASE_STORAGE_BUCKET", ""))
	supabaseStorageFolder = strings.Trim(strings.TrimSpace(getEnv("SUPABASE_STORAGE_FOLDER", "uploads")), "/")
	azureSpeechKey = strings.TrimSpace(getEnv("AZURE_SPEECH_KEY", ""))
	azureSpeechRegion = strings.TrimSpace(getEnv("AZURE_SPEECH_REGION", ""))
	azureSpeechDefault = strings.TrimSpace(getEnv("AZURE_SPEECH_DEFAULT_VOICE", "es-CO-SalomeNeural"))
	azureSpeechFormat = strings.TrimSpace(getEnv("AZURE_SPEECH_OUTPUT_FORMAT", "audio-24khz-96kbitrate-mono-mp3"))
	publicTTSEnabledFlag = getEnvBool("PUBLIC_TTS_ENABLED", false)
	ttsMaxCharsLimit = getEnvInt("TTS_MAX_CHARS", 700)
	ttsMinInterval = time.Duration(getEnvInt("TTS_MIN_INTERVAL_SECONDS", 20)) * time.Second
	trackInsertMinInterval = time.Duration(getEnvInt("TRACK_MIN_INTERVAL_SECONDS", 600)) * time.Second
	trackHeartbeatMinInterval = time.Duration(getEnvInt("TRACK_HEARTBEAT_MIN_INTERVAL_SECONDS", 300)) * time.Second

	attackerProfiles = make(map[string]*AttackerProfile)
	loginAttempts = make(map[string]int)

	// Cargar banco de escenarios en memoria (embedded en el binario)
	loadScenarioBankEmbed := func(data []byte, name string, dst *[]ScenarioItem) {
		var wrapper struct {
			Scenarios []ScenarioItem `json:"scenarios"`
		}
		if err := json.Unmarshal(data, &wrapper); err != nil {
			log.Printf("⚠️  Error parseando escenarios %s: %v", name, err)
			return
		}
		*dst = wrapper.Scenarios
		log.Printf("✅ %d escenarios cargados (%s)", len(*dst), name)
	}
	loadScenarioBankEmbed(scenarioUniversalJSON, "universal", &scenarioBankUniversal)
	loadScenarioBankEmbed(scenarioCiudadJSON, "ciudad", &scenarioBankCiudad)
	ttsLastRequestByIP = make(map[string]time.Time)
	publicAPICache = make(map[string]publicCacheEntry)
	trackLastEventByKey = make(map[string]time.Time)
	trackLastHeartbeatByKey = make(map[string]time.Time)
	publicHost := getEnv("PUBLIC_HOST", "bellatorrpg.online")

	router := mux.NewRouter()

	// ══════════════════════════════════════════════════════════════════════
	// RUTAS PÚBLICAS — acceso libre, sin autenticación
	// ══════════════════════════════════════════════════════════════════════
	router.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}).Methods("GET", "HEAD")
	router.HandleFunc("/api/track", trackVisitor).Methods("POST")
	router.HandleFunc("/api/telemetry", authHandler).Methods("POST")
	router.HandleFunc("/api/v1/auth", authHandler).Methods("POST")
	router.HandleFunc("/api/admin/login", banMiddleware(loginHandler)).Methods("POST")
	router.HandleFunc("/api/tts/voices", cachePublicResponse(5*time.Minute, listTTSVoicesHandler)).Methods("GET")
	router.HandleFunc("/api/tts/speak", speakTTSHandler).Methods("POST")

	// Escenario de batalla determinista
	router.HandleFunc("/api/escenario", escenarioAPIHandler).Methods("GET")
	router.HandleFunc("/api/image-proxy", scenarioImageProxyHandler).Methods("GET")

	// Datos públicos del torneo (sin PII)
	router.HandleFunc("/api/competidores", cachePublicResponse(20*time.Second, publicCompetidoresHandler)).Methods("GET")
	router.HandleFunc("/api/competidores-oficiales", cachePublicResponse(10*time.Second, officialQualifiedPlayersHandler)).Methods("GET")
	router.HandleFunc("/api/stats", cachePublicResponse(20*time.Second, publicStatsHandler)).Methods("GET")
	router.HandleFunc("/api/division-slots", cachePublicResponse(15*time.Second, divisionSlotsHandler)).Methods("GET")
	router.HandleFunc("/api/inscribir", inscribirHandler).Methods("POST")
	router.HandleFunc("/api/schedule", cachePublicResponse(60*time.Second, publicScheduleHandler)).Methods("GET")
	router.HandleFunc("/api/rankings", cachePublicResponse(30*time.Second, tournamentRankingsHandler)).Methods("GET")
	router.HandleFunc("/api/champions", cachePublicResponse(30*time.Second, tournamentChampionsHandler)).Methods("GET")
	router.HandleFunc("/api/fights", cachePublicResponse(20*time.Second, tournamentFightsHandler)).Methods("GET")
	router.HandleFunc("/api/bracket/results", cachePublicResponse(10*time.Second, getBracketResultsHandler)).Methods("GET")
	router.HandleFunc("/api/bets/fights", cachePublicResponse(10*time.Second, getOpenBetFightsHandler)).Methods("GET")
	router.HandleFunc("/api/bets/fights/{id}/details", cachePublicResponse(10*time.Second, getBetFightDetailsHandler)).Methods("GET")
	router.HandleFunc("/api/bets/stats", cachePublicResponse(15*time.Second, getBetsStatsHandler)).Methods("GET")
	
	// Álbum Bellator
	router.HandleFunc("/api/album/catalog", albumCatalogHandler).Methods("GET")
	router.HandleFunc("/api/album/config", albumConfigHandler).Methods("GET")
	router.HandleFunc("/api/album/me", albumMeHandler).Methods("GET")
	router.HandleFunc("/api/album/users", albumUsersHandler).Methods("GET")
	router.HandleFunc("/api/album/session", albumSessionGetHandler).Methods("GET")
	router.HandleFunc("/api/album/session", albumSessionCreateHandler).Methods("POST")
	router.HandleFunc("/api/album/register", albumRegisterHandler).Methods("POST")
	router.HandleFunc("/api/album/session", albumSessionDeleteHandler).Methods("DELETE")
	router.HandleFunc("/api/album/trades", albumTradeBoardHandler).Methods("GET")
	router.HandleFunc("/api/album/trades", albumTradePublishHandler).Methods("POST")
	router.HandleFunc("/api/album/trades/accept", albumTradeAcceptHandler).Methods("POST")
	router.HandleFunc("/api/album/collection", albumCollectionHandler).Methods("GET")
	router.HandleFunc("/api/album/open-pack", albumOpenPackHandler).Methods("POST")
	router.HandleFunc("/api/bets/my", myBetsHandler).Methods("GET")
	router.HandleFunc("/api/bets/place", placeBetHandler).Methods("POST")

	// Subida de imágenes (avatar / logo de clan)
	router.HandleFunc("/api/upload", uploadFileHandler).Methods("POST")

	// Admin panel dev-access (modo desarrollo: devuelve clave env en logs)
	router.HandleFunc("/admin/dev-access", adminDevAccessHandler).Methods("GET")

	// Clanes / Linajes
	router.HandleFunc("/api/clanes", cachePublicResponse(20*time.Second, getClanesHandler)).Methods("GET")
	router.HandleFunc("/api/clanes", createClanHandler).Methods("POST")
	router.HandleFunc("/api/clanes/{id}", editClanHandler).Methods("PATCH")
	router.HandleFunc("/api/clanes/{id}", deleteClanHandler).Methods("DELETE")
	router.Handle("/api/clanes/join", jwtMiddleware(http.HandlerFunc(joinClanHandler))).Methods("POST")
	router.Handle("/api/clanes/leave", jwtMiddleware(http.HandlerFunc(leaveClanHandler))).Methods("POST")
	router.HandleFunc("/api/players/bio", updatePlayerBioHandler).Methods("PATCH")
	router.HandleFunc("/api/players/profile", updatePlayerProfileHandler).Methods("PATCH")

	// Actualizar avatar / datos de jugador autenticado
	router.HandleFunc("/api/players/avatar", updatePlayerAvatarHandler).Methods("PATCH")

	// Documentación de la API
	router.HandleFunc("/api/docs", apiDocsHandler).Methods("GET")
	router.HandleFunc("/api", apiDocsHandler).Methods("GET")

	// ══════════════════════════════════════════════════════════════════════
	// RUTAS PROTEGIDAS — requieren JWT válido
	// ══════════════════════════════════════════════════════════════════════
	// Historial de combates
	router.HandleFunc("/api/combates", combatesHandler).Methods("GET")
	router.Handle("/api/admin/combate", jwtMiddleware(http.HandlerFunc(registrarCombateHandler))).Methods("POST")
	router.Handle("/api/admin/combate/{id}", jwtMiddleware(http.HandlerFunc(eliminarCombateHandler))).Methods("DELETE")
	router.Handle("/api/admin/combates-recientes", jwtMiddleware(http.HandlerFunc(combatesRecientesHandler))).Methods("GET")
	// Próximas peleas
	router.HandleFunc("/api/proximas-peleas", proximasPeleasHandler).Methods("GET")
	router.Handle("/api/admin/proxima-pelea", jwtMiddleware(http.HandlerFunc(crearProximaPeleaHandler))).Methods("POST")
	router.Handle("/api/admin/proxima-pelea/{id}", jwtMiddleware(http.HandlerFunc(eliminarProximaPeleaHandler))).Methods("DELETE")
	// Top personajes
	router.Handle("/api/admin/jugador/personajes", jwtMiddleware(http.HandlerFunc(actualizarPersonajesHandler))).Methods("POST")
	router.Handle("/api/admin/jugador/ranking", jwtMiddleware(http.HandlerFunc(actualizarRankingPointsHandler))).Methods("POST")
	router.Handle("/api/admin/player-keys/reset", jwtMiddleware(http.HandlerFunc(resetSinglePlayerKeyHandler))).Methods("POST")
	router.Handle("/api/admin/player-keys/reset-all", jwtMiddleware(http.HandlerFunc(resetAllPlayerKeysHandler))).Methods("POST")
	router.Handle("/api/admin/album/users", jwtMiddleware(http.HandlerFunc(adminAlbumUsersHandler))).Methods("GET")
	router.Handle("/api/admin/album/config", jwtMiddleware(http.HandlerFunc(adminAlbumConfigGetHandler))).Methods("GET")
	router.Handle("/api/admin/album/config", jwtMiddleware(http.HandlerFunc(adminAlbumConfigUpdateHandler))).Methods("POST")
	router.Handle("/api/admin/album/grant-packs", jwtMiddleware(http.HandlerFunc(adminAlbumGrantPacksHandler))).Methods("POST")
	router.Handle("/api/admin/bracket/result", jwtMiddleware(http.HandlerFunc(adminBracketResultHandler))).Methods("POST")
	router.Handle("/api/admin/bets", jwtMiddleware(http.HandlerFunc(adminBetsHandler))).Methods("GET")
	
	// Admin: eliminar jugador
	router.Handle("/api/admin/jugador/{pseudonimo}", jwtMiddleware(http.HandlerFunc(eliminarJugadorHandler))).Methods("DELETE")

	router.Handle("/api/visitors", jwtMiddleware(http.HandlerFunc(getVisitors))).Methods("GET")
	router.Handle("/api/attackers", jwtMiddleware(http.HandlerFunc(getAttackers))).Methods("GET")
	router.Handle("/api/admin/geo", jwtMiddleware(http.HandlerFunc(adminGeoBatchHandler))).Methods("POST")

	// ══════════════════════════════════════════════════════════════════════
	// ARCHIVOS ESTÁTICOS
	// ══════════════════════════════════════════════════════════════════════
	router.HandleFunc("/", serveFile("./public/index.html")).Methods("GET")
	router.HandleFunc("/index.html", serveFile("./public/index.html")).Methods("GET")
	router.HandleFunc("/registro", serveFile("./public/registro.html")).Methods("GET")
	router.HandleFunc("/competidores", serveFile("./public/competidores.html")).Methods("GET")
	router.HandleFunc("/competidor", serveFile("./public/competidor.html")).Methods("GET")
	router.HandleFunc("/clasificacion", serveFile("./public/clasificacion.html")).Methods("GET")
	router.HandleFunc("/cosmologias", serveFile("./public/cosmologias.html")).Methods("GET")
	router.HandleFunc("/cosmologias.html", serveFile("./public/cosmologias.html")).Methods("GET")
	router.HandleFunc("/reglamento", serveFile("./public/reglamento.html")).Methods("GET")
	router.HandleFunc("/reglamento-lectura", serveFile("./public/reglamento-lectura.html")).Methods("GET")
	router.HandleFunc("/sorteo", serveFile("./public/sorteo.html")).Methods("GET")
	router.HandleFunc("/sorteo.html", serveFile("./public/sorteo.html")).Methods("GET")
	router.HandleFunc("/escenario", serveFile("./public/escenario.html")).Methods("GET")
	router.HandleFunc("/escenario.html", serveFile("./public/escenario.html")).Methods("GET")
	router.HandleFunc("/practica", serveFile("./public/practica.html")).Methods("GET")
	router.HandleFunc("/admision", serveFile("./public/admision.html")).Methods("GET")
	router.HandleFunc("/examen", serveFile("./public/examen.html")).Methods("GET")
	router.HandleFunc("/examen-universal", serveFile("./public/examen-universal.html")).Methods("GET")
	router.HandleFunc("/album-demo", serveFile("./public/album-demo.html")).Methods("GET")
	router.HandleFunc("/album2", serveFile("./public/album2.html")).Methods("GET")
	router.HandleFunc("/apuestas", serveFile("./public/apuestas.html")).Methods("GET")
	router.HandleFunc("/apuestas.html", serveFile("./public/apuestas.html")).Methods("GET")
	router.HandleFunc("/clanes", serveFile("./public/clanes.html")).Methods("GET")
	router.Handle("/bl-sentinel-9f3a2c", http.HandlerFunc(serveFile("./public/admin.html"))).Methods("GET")

	// Cualquier intento de /admin.html → 404 puro (no revela nada)
	router.HandleFunc("/admin.html", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}).Methods("GET")
	router.HandleFunc("/shared.css", serveFile("./public/shared.css")).Methods("GET")
	router.HandleFunc("/core.js", serveFile("./public/core.js")).Methods("GET")
	router.HandleFunc("/sorteo-algo.js", serveFile("./public/sorteo-algo.js")).Methods("GET")
	router.HandleFunc("/sentinel.js", serveFile("./public/sentinel.js")).Methods("GET")
	router.HandleFunc("/robots.txt", serveFile("./public/robots.txt")).Methods("GET")
	router.HandleFunc(opaqueAppAssetPath, serveOpaqueAssetFile("./public/app.js")).Methods("GET")
	router.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}).Methods("GET")
	router.HandleFunc("/tts-client.js", serveFile("./public/tts-client.js")).Methods("GET")
	router.HandleFunc(opaqueTrackerAssetPath, serveOpaqueAssetFile("./public/tracker.js")).Methods("GET")
	router.HandleFunc("/tracker.js", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}).Methods("GET")
	router.HandleFunc("/translate.js", serveFile("./public/translate.js")).Methods("GET")
	router.HandleFunc("/audio/bellator-intro.mp3", serveFileOrCDN("./public/audio/bellator-intro.mp3", "/audio/bellator-intro.mp3")).Methods("GET")
	router.HandleFunc("/audio/let-go.mp3", serveFileOrCDN("./public/audio/let-go.mp3", "/audio/let-go.mp3")).Methods("GET")
	router.HandleFunc("/audio/goth-slowed.mp3", serveFileOrCDN("./public/audio/goth-slowed.mp3", "/audio/goth-slowed.mp3")).Methods("GET")
	router.HandleFunc("/register-fight-loop.mp4", serveFileOrCDN("./public/register-fight-loop.mp4", "/register-fight-loop.mp4")).Methods("GET")
	router.HandleFunc("/404alert.jpg", serveFile("./public/404alert.jpg")).Methods("GET")
	router.HandleFunc("/iliaaa.jpg", serveFile("./public/iliaaa.jpg")).Methods("GET")
	router.HandleFunc("/editmisterbug.png", serveFile("./public/editmisterbug.png")).Methods("GET")
	router.HandleFunc("/fondocarnet.avif", serveFile("./public/fondocarnet.avif")).Methods("GET")
	router.HandleFunc("/57d72016-63a4-4b62-86e7-464c84ec3fac.png", serveFile("./public/57d72016-63a4-4b62-86e7-464c84ec3fac.png")).Methods("GET")

	// Bloquear acceso a 404.html — devuelve 404 real
	router.HandleFunc("/404.html", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}).Methods("GET")

	// Favicon - devolver 204 No Content para evitar 404
	router.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}).Methods("GET")

	// Servir uploads de imágenes de usuarios y clanes
	uploadsDir := http.StripPrefix("/uploads/", http.FileServer(http.Dir("./public/uploads")))
	router.PathPrefix("/uploads/").Handler(uploadsDir).Methods("GET")

	// Servir JSON de escenarios de batalla (public/data/)
	dataDir := http.StripPrefix("/data/", http.FileServer(http.Dir("./public/data")))
	router.PathPrefix("/data/").Handler(dataDir).Methods("GET")

	// Algunos verificadores (Meta/Facebook) prueban primero con HEAD.
	// Normalizamos HEAD->GET para evitar 405 en páginas estáticas.
	headCompat := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			r2 := r.Clone(r.Context())
			r2.Method = http.MethodGet
			router.ServeHTTP(w, r2)
			return
		}
		router.ServeHTTP(w, r)
	})

	// CORS
	allowedOrigins := []string{
		"https://" + publicHost,
		"https://www." + publicHost,
		"https://valhala-album.netlify.app",
		"https://valhala-album-2026.netlify.app",
		"http://localhost:8091",
		"http://127.0.0.1:8091",
	}
	handler := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "HEAD", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Player-Key"},
		AllowCredentials: true,
	}).Handler(headCompat)
	handler = forceHTTPS(publicHost, handler)

	port := getEnv("PORT", "8080") // Para hosting como Railway/Render
	fmt.Printf("🚀 Servidor ejecutándose en puerto %s\n", port)
	fmt.Println("📊 Panel de administración: https://[tu-dominio]/bl-sentinel-9f3a2c")
	fmt.Println("🔒 Sistema de rastreo ACTIVO con persistencia Supabase")

	log.Fatal(http.ListenAndServe(":"+port, handler))
}

// seededScenarioIndex replica el algoritmo xmur3 + mulberry32 del frontend
// para seleccionar un escenario de forma determinista dado un seed string.
func seededScenarioIndex(seed string, poolSize int) int {
	if poolSize == 0 {
		return 0
	}
	// xmur3: hash de la cadena
	h := uint32(1779033703) ^ uint32(len(seed))
	for i := 0; i < len(seed); i++ {
		h = (h ^ uint32(seed[i])) * 3432918353
		h = (h << 13) | (h >> 19)
	}
	// xmur3 finalización (llamada una vez)
	h = (h ^ (h >> 16)) * 2246822507
	h = (h ^ (h >> 13)) * 3266489909
	h ^= h >> 16
	// mulberry32: una iteración con h como semilla
	h += 0x6D2B79F5
	t := (h ^ (h >> 15)) * (1 | h)
	t ^= t + (t^(t>>7))*(61|t)
	t ^= t >> 14
	return int(float64(t) / 4294967296.0 * float64(poolSize))
}

// escenarioAPIHandler devuelve el escenario determinista para una batalla dada.
func escenarioAPIHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p1 := strings.ToLower(strings.TrimSpace(q.Get("p1")))
	p2 := strings.ToLower(strings.TrimSpace(q.Get("p2")))
	division := strings.ToLower(strings.TrimSpace(q.Get("division")))
	round := strings.TrimSpace(q.Get("round"))
	torneo := strings.TrimSpace(q.Get("torneo"))

	if round == "" {
		round = "1"
	}
	if torneo == "" {
		torneo = "bellator"
	}
	if division != "ciudad" {
		division = "universal"
	}

	pool := scenarioBankUniversal
	if division == "ciudad" {
		pool = scenarioBankCiudad
	}

	if len(pool) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"banco de escenarios no disponible"}`))
		return
	}

	seed := torneo + "|" + division + "|" + round + "|" + p1 + "|" + p2
	idx := seededScenarioIndex(seed, len(pool))
	scenario := pool[idx]

	resp := map[string]interface{}{
		"scenario":  scenario,
		"seed":      seed,
		"index":     idx,
		"pool_size": len(pool),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("escenarioAPIHandler encode error: %v", err)
	}
}

func isAllowedScenarioImageProxyHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(hostWithoutPort(host)))
	if h == "" {
		return false
	}
	switch h {
	case "static.wikia.nocookie.net", "vignette.wikia.nocookie.net", "vsbattles.fandom.com":
		return true
	default:
		return false
	}
}

func scenarioImageProxyHandler(w http.ResponseWriter, r *http.Request) {
	rawURL := strings.TrimSpace(r.URL.Query().Get("url"))
	if rawURL == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		http.Error(w, "unsupported scheme", http.StatusBadRequest)
		return
	}
	if !isAllowedScenarioImageProxyHost(parsed.Host) {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, parsed.String(), nil)
	if err != nil {
		http.Error(w, "request build failed", http.StatusInternalServerError)
		return
	}
	req.Header.Set("User-Agent", "BellatorImageProxy/1.0")

	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "upstream fetch failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}

	contentType := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if contentType == "" || !strings.HasPrefix(contentType, "image/") {
		http.Error(w, "upstream is not an image", http.StatusUnsupportedMediaType)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	if contentLen := strings.TrimSpace(resp.Header.Get("Content-Length")); contentLen != "" {
		w.Header().Set("Content-Length", contentLen)
	}

	_, _ = io.Copy(w, io.LimitReader(resp.Body, 15<<20))
}

func serveFile(fp string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(fp, ".html"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		case strings.HasSuffix(fp, ".css"):
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case strings.HasSuffix(fp, ".js"):
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		}
		http.ServeFile(w, r, fp)
	}
}

func serveOpaqueAssetFile(fp string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		http.ServeFile(w, r, fp)
	}
}

func serveFileOrCDN(localPath, cdnPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(localPath); err == nil {
			http.ServeFile(w, r, localPath)
			return
		}

		cdnURL := "https://cdn.jsdelivr.net/gh/DanielMunoz9/pqsipqsi@main/public" + cdnPath
		http.Redirect(w, r, cdnURL, http.StatusFound)
	}
}

func azureSpeechEnabled() bool {
	return azureSpeechKey != "" && azureSpeechRegion != ""
}

func publicTTSEnabled() bool {
	return publicTTSEnabledFlag && azureSpeechEnabled()
}

func normalizeTTSText(text string) string {
	clean := strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	if clean == "" {
		return ""
	}
	runes := []rune(clean)
	limit := ttsMaxCharsLimit
	if limit <= 0 {
		limit = 700
	}
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return clean
}

func requestClientIP(r *http.Request) string {
	rawIP := r.Header.Get("CF-Connecting-IP")
	if rawIP == "" {
		rawIP = r.Header.Get("X-Forwarded-For")
	}
	if rawIP == "" {
		rawIP = r.Header.Get("X-Real-IP")
	}
	if rawIP == "" {
		rawIP = r.RemoteAddr
	}
	clientIP := cleanIPPort(rawIP)
	if clientIP == "::1" || clientIP == "127.0.0.1" || clientIP == "[::1]" {
		if pub := cleanIPPort(getPublicIP()); pub != "" {
			return pub
		}
	}
	return clientIP
}

func compactAuditValue(value string, maxRunes int) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "-"
	}
	if maxRunes <= 4 {
		maxRunes = 4
	}
	runes := []rune(trimmed)
	if len(runes) <= maxRunes {
		return trimmed
	}
	return string(runes[:maxRunes-3]) + "..."
}

func hasMeaningfulAuditValue(value interface{}) bool {
	return normalizeNullableString(value) != ""
}

func blockedTelemetryFieldNames(values map[string]interface{}) []string {
	blocked := make([]string, 0, len(values))
	for key, value := range values {
		if _, ok := telemetryAuditWritableColumns[key]; ok {
			continue
		}
		if !hasMeaningfulAuditValue(value) {
			continue
		}
		blocked = append(blocked, key)
	}
	sort.Strings(blocked)
	return blocked
}

func auditAvatarSource(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "cleared"
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(trimmed, "/uploads/") {
		return "upload"
	}
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return "remote"
	}
	return "other"
}

func resolveAzureVoice(requestedID string) NarratorVoice {
	requestedID = strings.TrimSpace(requestedID)
	if requestedID != "" {
		for _, voice := range azureNarratorVoices {
			if voice.ID == requestedID {
				return voice
			}
		}
	}
	for _, voice := range azureNarratorVoices {
		if voice.ID == azureSpeechDefault {
			return voice
		}
	}
	return azureNarratorVoices[0]
}

func listTTSVoicesHandler(w http.ResponseWriter, _ *http.Request) {
	if !publicTTSEnabled() {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"enabled":      false,
			"provider":     "azure",
			"defaultVoice": "",
			"voices":       []NarratorVoice{},
		})
		return
	}

	defaultVoice := resolveAzureVoice("")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":      true,
		"provider":     "azure",
		"defaultVoice": defaultVoice.ID,
		"voices":       azureNarratorVoices,
	})
}

func azureSpeechEndpoint() string {
	return fmt.Sprintf("https://%s.tts.speech.microsoft.com/cognitiveservices/v1", azureSpeechRegion)
}

func buildAzureSSML(text string, voice NarratorVoice) string {
	escaped := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
	).Replace(text)
	lang := voice.Lang
	if lang == "" {
		lang = "es-CO"
	}
	return fmt.Sprintf("<speak version='1.0' xml:lang='%s' xmlns='http://www.w3.org/2001/10/synthesis'><voice name='%s'>%s</voice></speak>", lang, voice.ID, escaped)
}

func synthesizeAzureSpeech(text string, voice NarratorVoice) ([]byte, error) {
	if !azureSpeechEnabled() {
		return nil, fmt.Errorf("azure speech no esta configurado")
	}

	ssml := buildAzureSSML(text, voice)
	req, err := http.NewRequest(http.MethodPost, azureSpeechEndpoint(), bytes.NewBufferString(ssml))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Ocp-Apim-Subscription-Key", azureSpeechKey)
	req.Header.Set("Content-Type", "application/ssml+xml")
	req.Header.Set("X-Microsoft-OutputFormat", azureSpeechFormat)
	req.Header.Set("User-Agent", "BellatorNarrator/1.0")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("azure speech %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func speakTTSHandler(w http.ResponseWriter, r *http.Request) {
	if !publicTTSEnabled() {
		http.Error(w, "TTS publico deshabilitado en el servidor", http.StatusServiceUnavailable)
		return
	}

	if ttsMinInterval > 0 {
		clientIP := requestClientIP(r)
		if clientIP != "" {
			now := time.Now()
			ttsRateLimitMu.Lock()
			lastSeen := ttsLastRequestByIP[clientIP]
			if !lastSeen.IsZero() && now.Sub(lastSeen) < ttsMinInterval {
				retryAfter := int((ttsMinInterval - now.Sub(lastSeen) + time.Second - 1) / time.Second)
				ttsRateLimitMu.Unlock()
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				http.Error(w, "TTS temporalmente limitado", http.StatusTooManyRequests)
				return
			}
			ttsLastRequestByIP[clientIP] = now
			ttsRateLimitMu.Unlock()
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	defer r.Body.Close()

	var payload TTSSpeakPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Payload TTS invalido", http.StatusBadRequest)
		return
	}

	text := normalizeTTSText(payload.Text)
	if text == "" {
		http.Error(w, "No hay texto para narrar", http.StatusBadRequest)
		return
	}

	voice := resolveAzureVoice(payload.Voice)
	audioBytes, err := synthesizeAzureSpeech(text, voice)
	if err != nil {
		log.Printf("azure-tts: error sintetizando con %s: %v", voice.ID, err)
		http.Error(w, "Fallo la sintesis de voz", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "audio/mpeg")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	w.Header().Set("X-TTS-Voice", voice.ID)
	w.Header().Set("X-TTS-Provider", "azure")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(audioBytes)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func newPublicResponseRecorder() *publicResponseRecorder {
	return &publicResponseRecorder{
		header: make(http.Header),
		status: http.StatusOK,
	}
}

func (recorder *publicResponseRecorder) Header() http.Header {
	return recorder.header
}

func (recorder *publicResponseRecorder) WriteHeader(status int) {
	recorder.status = status
}

func (recorder *publicResponseRecorder) Write(body []byte) (int, error) {
	return recorder.body.Write(body)
}

func cloneHTTPHeader(header http.Header) http.Header {
	cloned := make(http.Header, len(header))
	for key, values := range header {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func copyHTTPHeader(dst, src http.Header) {
	for key, values := range src {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func publicCacheControlValue(ttl time.Duration) string {
	seconds := int(ttl / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("public, max-age=%d, stale-while-revalidate=%d", seconds, seconds)
}

func writePublicResponse(w http.ResponseWriter, status int, header http.Header, body []byte, ttl time.Duration, cacheState string) {
	copyHTTPHeader(w.Header(), header)
	w.Header().Set("X-Bellator-Cache", cacheState)
	if status >= 200 && status < 300 && w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", publicCacheControlValue(ttl))
	}
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func getCachedPublicResponse(key string, now time.Time) (publicCacheEntry, bool) {
	publicAPICacheMu.RLock()
	entry, ok := publicAPICache[key]
	publicAPICacheMu.RUnlock()
	if !ok {
		return publicCacheEntry{}, false
	}
	if !entry.ExpiresAt.After(now) {
		publicAPICacheMu.Lock()
		current, found := publicAPICache[key]
		if found && !current.ExpiresAt.After(now) {
			delete(publicAPICache, key)
		}
		publicAPICacheMu.Unlock()
		return publicCacheEntry{}, false
	}
	return entry, true
}

func storeCachedPublicResponse(key string, recorder *publicResponseRecorder, ttl time.Duration, now time.Time) {
	bodyCopy := append([]byte(nil), recorder.body.Bytes()...)
	entry := publicCacheEntry{
		Status:    recorder.status,
		Header:    cloneHTTPHeader(recorder.header),
		Body:      bodyCopy,
		ExpiresAt: now.Add(ttl),
	}
	publicAPICacheMu.Lock()
	publicAPICache[key] = entry
	if len(publicAPICache) > 256 {
		for cacheKey, cached := range publicAPICache {
			if !cached.ExpiresAt.After(now) {
				delete(publicAPICache, cacheKey)
			}
		}
	}
	publicAPICacheMu.Unlock()
}

func invalidateCachedPublicResponses(prefixes ...string) {
	if len(prefixes) == 0 {
		return
	}
	publicAPICacheMu.Lock()
	defer publicAPICacheMu.Unlock()
	for cacheKey := range publicAPICache {
		requestKey := cacheKey
		if strings.HasPrefix(requestKey, http.MethodGet+":") {
			requestKey = strings.TrimPrefix(requestKey, http.MethodGet+":")
		}
		for _, prefix := range prefixes {
			trimmedPrefix := strings.TrimSpace(prefix)
			if trimmedPrefix == "" {
				continue
			}
			if strings.HasPrefix(requestKey, trimmedPrefix) {
				delete(publicAPICache, cacheKey)
				break
			}
		}
	}
}

func cachePublicResponse(ttl time.Duration, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ttl <= 0 || r.Method != http.MethodGet {
			next(w, r)
			return
		}

		now := time.Now()
		cacheKey := r.Method + ":" + r.URL.RequestURI()
		if entry, ok := getCachedPublicResponse(cacheKey, now); ok {
			writePublicResponse(w, entry.Status, entry.Header, entry.Body, ttl, "HIT")
			return
		}

		recorder := newPublicResponseRecorder()
		next(recorder, r)

		body := recorder.body.Bytes()
		cacheable := recorder.status >= 200 && recorder.status < 300 && len(body) <= 1<<20
		if cacheable {
			storeCachedPublicResponse(cacheKey, recorder, ttl, now)
		}

		cacheState := "BYPASS"
		if cacheable {
			cacheState = "MISS"
		}
		writePublicResponse(w, recorder.status, recorder.header, body, ttl, cacheState)
	}
}

func makeTrackIdentityKey(connIP, userAgent, hardwareFingerprint string) string {
	trimmedFingerprint := strings.TrimSpace(hardwareFingerprint)
	if trimmedFingerprint != "" {
		hash := sha256.Sum256([]byte("fp\n" + trimmedFingerprint))
		return "fp:" + hex.EncodeToString(hash[:8])
	}

	trimmedIP := strings.TrimSpace(connIP)
	trimmedUserAgent := strings.TrimSpace(userAgent)
	if trimmedIP == "" && trimmedUserAgent == "" {
		return ""
	}

	hash := sha256.Sum256([]byte(trimmedIP + "\n" + trimmedUserAgent))
	return "ipua:" + hex.EncodeToString(hash[:8])
}

func pruneTrackWindowsLocked(cutoff time.Time) {
	for key, lastSeen := range trackLastEventByKey {
		if lastSeen.Before(cutoff) {
			delete(trackLastEventByKey, key)
		}
	}
	for key, lastSeen := range trackLastHeartbeatByKey {
		if lastSeen.Before(cutoff) {
			delete(trackLastHeartbeatByKey, key)
		}
	}
}

func shouldSampleTrack(identityKey string, heartbeat bool, now time.Time) bool {
	if identityKey == "" {
		return false
	}

	trackWindowMu.Lock()
	defer trackWindowMu.Unlock()

	if heartbeat {
		if trackHeartbeatMinInterval > 0 {
			if lastSeen := trackLastHeartbeatByKey[identityKey]; !lastSeen.IsZero() && now.Sub(lastSeen) < trackHeartbeatMinInterval {
				return true
			}
			trackLastHeartbeatByKey[identityKey] = now
		}
	} else {
		if trackInsertMinInterval > 0 {
			if lastSeen := trackLastEventByKey[identityKey]; !lastSeen.IsZero() && now.Sub(lastSeen) < trackInsertMinInterval {
				return true
			}
			trackLastEventByKey[identityKey] = now
		}
	}

	if len(trackLastEventByKey)+len(trackLastHeartbeatByKey) > 4096 {
		pruneTrackWindowsLocked(now.Add(-24 * time.Hour))
	}
	return false
}

func trackVisitor(w http.ResponseWriter, r *http.Request) {
	// ── 1. OBTENER IP DE CONEXIÓN (Priorizando Cloudflare/Proxies) ──────
	connIP := requestClientIP(r)

	// ── 2. ATRIBUCIÓN DE CAMPAÑA (fbclid + Referer) ──────────────────────
	fbClickID, trafficSource := extractCampaignData(r)

	// ── 3. LEER DATOS DEL NAVEGADOR ──────────────────────────────────────
	var browserData map[string]interface{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	if err := json.Unmarshal(body, &browserData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// ── 4. HARDWARE FINGERPRINT (canvas SHA-256 desde JS) ────────────────
	hardwareFingerprint := getStringFromMap(browserData, "hardwareFingerprint")
	now := time.Now()
	timestamp := now.Format(time.RFC3339)
	userAgent := getStringFromMap(browserData, "userAgent")
	if userAgent == "" {
		userAgent = strings.TrimSpace(r.UserAgent())
	}
	identityKey := makeTrackIdentityKey(connIP, userAgent, hardwareFingerprint)
	isHeartbeat, _ := browserData["is_heartbeat"].(bool)

	// ── 4b. HEARTBEAT: solo actualizar timestamp, no duplicar registro ────
	if isHeartbeat {
		if shouldSampleTrack(identityKey, true, now) {
			writeJSON(w, http.StatusAccepted, map[string]interface{}{"heartbeat": true, "sampled": true})
			return
		}
		if hardwareFingerprint == "" {
			writeJSON(w, http.StatusAccepted, map[string]interface{}{"heartbeat": true, "ignored": true})
			return
		}
		go func() {
			update := map[string]string{
				"timestamp": timestamp,
			}
			var res []VisitorData
			_, e := supabaseClient.From("audit_logs").
				Update(update, "", "").
				Filter("hardware_fingerprint", "eq", hardwareFingerprint).
				ExecuteTo(&res)
			if e != nil {
				log.Printf("⚠️ Error heartbeat UPSERT: %v", e)
			}
		}()
		writeJSON(w, http.StatusOK, map[string]interface{}{"heartbeat": true, "sampled": false})
		return
	}

	if shouldSampleTrack(identityKey, false, now) {
		writeJSON(w, http.StatusAccepted, map[string]interface{}{"success": true, "sampled": true})
		return
	}

	// ── 5. DETECCIÓN DE DISCREPANCIA DE IP (VPN via WebRTC STUN) ─────────
	realPublicIP := getStringFromMap(browserData, "realPublicIP")
	vpnDetected := false
	realIPHash := ""
	vpnIPHash := ""
	if realPublicIP != "" && realPublicIP != "error" && realPublicIP != "timeout" &&
		realPublicIP != "not-supported" && !isPrivateIP(realPublicIP) {
		realIPHash = hashIP(realPublicIP)
		// Si connIP era loopback y ahora es la IP pública del servidor,
		// puede coincidir con la del cliente → no es VPN, es localhost
		localhostConn := (r.RemoteAddr == "::1" || strings.HasPrefix(r.RemoteAddr, "127.") || strings.HasPrefix(r.RemoteAddr, "[::1]"))
		if !localhostConn && connIP != realPublicIP {
			vpnDetected = true
			vpnIPHash = hashIP(connIP)
			log.Printf("🔍 Discrepancia IP detectada → VPN_DETECTED=true")
		}
	}

	// ── 6. INTELIGENCIA DE AMENAZAS ───────────────────────────────────────
	// getIPInfo no se usa para persistencia — solo se llama detectVPN una vez
	vpnData := detectVPN(connIP)

	// Verificar IP real (la que no pasa por VPN) contra Spamhaus
	checkIP := connIP
	if realPublicIP != "" && !isPrivateIP(realPublicIP) {
		checkIP = realPublicIP
	}
	spamhausStatus := checkSpamhausXBL(checkIP)

	// ── 7. PERFIL DE ATACANTE (agrupación por hardware fingerprint) ───────
	isKnownAttacker, groupID := trackAttackerProfile(hardwareFingerprint, hashIP(connIP), fbClickID)
	displayIP := realPublicIP
	if displayIP == "" || displayIP == "error" || displayIP == "timeout" || displayIP == "not-supported" || isPrivateIP(displayIP) {
		displayIP = connIP
	}

	// ── 8. CREAR REGISTRO ANONIMIZADO (IPs como SHA-256) ─────────────────
	visitor := VisitorData{
		ID:                  now.UnixNano(),
		Timestamp:           timestamp,
		IP:                  hashIP(connIP),
		RealIPHash:          realIPHash,
		VPNIPHash:           vpnIPHash,
		IPInfo:              nil,
		BrowserData:         browserData,
		IsVPN:               vpnData["isVPN"].(bool) || vpnDetected,
		ProxyType:           vpnData["proxyType"].(string),
		RiskScore:           vpnData["riskScore"].(int),
		FBClickID:           fbClickID,
		TrafficSource:       trafficSource,
		HardwareFingerprint: hardwareFingerprint,
		SpamhausStatus:      spamhausStatus,
		KnownAttacker:       isKnownAttacker,
		AttackerGroupID:     groupID,
		VPNDetected:         vpnDetected,
	}

	// Construir fila con columnas reales de Supabase e insertar de forma asíncrona
	row := DBRow{
		ID:                  visitor.ID,
		Timestamp:           visitor.Timestamp,
		FBClickID:           visitor.FBClickID,
		IPConexionHash:      visitor.IP, // hash del IP de conexión (GDPR)
		IPRealWebRTC:        displayIP,  // IP visible en admin (WebRTC o fallback de conexión)
		HardwareFingerprint: visitor.HardwareFingerprint,
		VPNDetectada:        visitor.IsVPN || visitor.VPNDetected,
		SpamhausStatus:      visitor.SpamhausStatus,
		UserAgent:           userAgent,
		GPSLocation:         getStringFromMap(browserData, "gpsLocation"),
	}
	go func() {
		var result []DBRow
		_, err := supabaseClient.From("audit_logs").Insert(row, false, "", "", "").ExecuteTo(&result)
		if err != nil {
			log.Printf("⚠️ Error insertando en Supabase (trackVisitor): %v", err)
		}
	}()

	log.Printf("✅ Track (Supabase): ID=%d | src=%s | fbclid=%q | spamhaus=%s | knownAttacker=%v | vpn=%v",
		visitor.ID, visitor.TrafficSource, visitor.FBClickID, visitor.SpamhausStatus, visitor.KnownAttacker, vpnDetected)
	if spamhausStatus != "clean" && spamhausStatus != "ipv6_skipped" {
		log.Printf("🦠 BOTNET/MALWARE Spamhaus: %s", spamhausStatus)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"id":      visitor.ID,
	})
}

func getVisitors(w http.ResponseWriter, r *http.Request) {
	var results []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").Select("*", "", false).Order("timestamp", &postgrest.OrderOpts{Ascending: false}).Limit(100, "").ExecuteTo(&results)
	if err != nil {
		log.Printf("⚠️ Error obteniendo visitantes de Supabase: %v", err)
		http.Error(w, "Error al contactar la base de datos", http.StatusInternalServerError)
		return
	}
	enrichVisitorResultsWithTelemetry(results)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func adminGeoBatchHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"petición inválida"}`, http.StatusBadRequest)
		return
	}

	seen := make(map[string]struct{})
	cleanIPs := make([]string, 0, len(body.IPs))
	for _, rawIP := range body.IPs {
		ip := cleanIPPort(strings.TrimSpace(rawIP))
		if ip == "" || isPrivateIP(ip) {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		cleanIPs = append(cleanIPs, ip)
		if len(cleanIPs) >= 100 {
			break
		}
	}

	if len(cleanIPs) == 0 {
		writeJSON(w, http.StatusOK, []map[string]interface{}{})
		return
	}

	results := make([]map[string]interface{}, 0, len(cleanIPs))
	client := &http.Client{Timeout: 6 * time.Second}
	for _, ip := range cleanIPs {
		if cached, ok := getAdminGeoCache(ip); ok {
			results = append(results, cached)
			continue
		}

		resolved, err := resolveAdminGeo(client, ip)
		if err != nil {
			log.Printf("⚠️ Error resolviendo geolocalización admin para %s: %v", ip, err)
			resolved = map[string]interface{}{
				"status": "fail",
				"query":  ip,
			}
		}
		cacheAdminGeo(ip, resolved, 30*time.Minute)
		results = append(results, resolved)
	}

	writeJSON(w, http.StatusOK, results)
}

func getAdminGeoCache(ip string) (map[string]interface{}, bool) {
	if value, ok := adminGeoCache.Load(ip); ok {
		entry, ok := value.(adminGeoCacheEntry)
		if ok && time.Now().Before(entry.ExpiresAt) {
			return entry.Data, true
		}
		adminGeoCache.Delete(ip)
	}
	return nil, false
}

func cacheAdminGeo(ip string, data map[string]interface{}, ttl time.Duration) {
	if ip == "" || data == nil {
		return
	}
	adminGeoCache.Store(ip, adminGeoCacheEntry{
		Data:      data,
		ExpiresAt: time.Now().Add(ttl),
	})
}

func resolveAdminGeo(client *http.Client, ip string) (map[string]interface{}, error) {
	if client == nil {
		client = &http.Client{Timeout: 6 * time.Second}
	}

	req, err := http.NewRequest(http.MethodGet, "https://ipwho.is/"+url.PathEscape(ip), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("geo upstream status %d", resp.StatusCode)
	}

	var geo ipWhoisResponse
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return nil, err
	}

	if !geo.Success {
		return map[string]interface{}{
			"status": "fail",
			"query":  ip,
		}, nil
	}

	return map[string]interface{}{
		"status":      "success",
		"country":     geo.Country,
		"countryCode": geo.CountryCode,
		"city":        geo.City,
		"isp":         geo.Connection.ISP,
		"query":       geo.IP,
	}, nil
}

func getIPInfo(ip string) map[string]interface{} {
	// Limpiar la IP (remover puerto si existe)
	if idx := strings.Index(ip, ":"); idx != -1 && !strings.HasPrefix(ip, "[") {
		ip = ip[:idx]
	}
	if strings.HasPrefix(ip, "[") {
		if idx := strings.Index(ip, "]"); idx != -1 {
			ip = ip[1:idx]
		}
	}

	// Usar ProxyCheck.io API (gratis hasta 1000 requests/día)
	url := fmt.Sprintf("https://proxycheck.io/v2/%s?vpn=1&asn=1&risk=1", ip)

	resp, err := http.Get(url)
	if err != nil {
		log.Printf("⚠️  Error obteniendo datos de IP: %v", err)
		return map[string]interface{}{}
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("⚠️  Error leyendo respuesta de IP: %v", err)
		return map[string]interface{}{}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Printf("⚠️  Error parseando datos de IP: %v", err)
		return map[string]interface{}{}
	}

	return data
}

func getPublicIP() string {
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return string(body)
}

func detectVPN(ip string) map[string]interface{} {
	// Limpiar la IP
	if idx := strings.Index(ip, ":"); idx != -1 && !strings.HasPrefix(ip, "[") {
		ip = ip[:idx]
	}
	if strings.HasPrefix(ip, "[") {
		if idx := strings.Index(ip, "]"); idx != -1 {
			ip = ip[1:idx]
		}
	}

	// Usar ProxyCheck.io API (gratis hasta 1000 requests/día)
	url := fmt.Sprintf("https://proxycheck.io/v2/%s?vpn=1&asn=1&risk=1", ip)

	resp, err := http.Get(url)
	if err != nil {
		log.Printf("⚠️  Error detectando VPN: %v", err)
		return map[string]interface{}{
			"isVPN":     false,
			"proxyType": "unknown",
			"riskScore": 0,
		}
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("⚠️  Error leyendo respuesta VPN: %v", err)
		return map[string]interface{}{
			"isVPN":     false,
			"proxyType": "unknown",
			"riskScore": 0,
		}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Printf("⚠️  Error parseando datos VPN: %v", err)
		return map[string]interface{}{
			"isVPN":     false,
			"proxyType": "unknown",
			"riskScore": 0,
		}
	}

	// Extraer datos de la respuesta
	if ipData, ok := data[ip].(map[string]interface{}); ok {
		isProxy := false
		proxyType := "clean"
		riskScore := 0

		if proxy, exists := ipData["proxy"]; exists && proxy == "yes" {
			isProxy = true
			if pType, ok := ipData["type"].(string); ok {
				proxyType = pType
			}
		}

		if risk, ok := ipData["risk"].(float64); ok {
			riskScore = int(risk)
		}

		return map[string]interface{}{
			"isVPN":     isProxy,
			"proxyType": proxyType,
			"riskScore": riskScore,
		}
	}

	return map[string]interface{}{
		"isVPN":     false,
		"proxyType": "clean",
		"riskScore": 0,
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// FUNCIONES DE FRAUD DETECTION & BOT MITIGATION
// ═══════════════════════════════════════════════════════════════════════════

// cleanIPPort elimina el puerto de una dirección "IP:puerto"
func cleanIPPort(ipPort string) string {
	ipPort = strings.TrimSpace(ipPort)
	if idx := strings.Index(ipPort, ","); idx != -1 {
		ipPort = strings.TrimSpace(ipPort[:idx])
	}
	if strings.HasPrefix(ipPort, "[") {
		// IPv6 en formato [::1]:port
		if end := strings.Index(ipPort, "]"); end != -1 {
			return ipPort[1:end]
		}
	}
	if strings.Count(ipPort, ":") == 1 {
		// IPv4:port
		if idx := strings.LastIndex(ipPort, ":"); idx != -1 {
			return ipPort[:idx]
		}
	}
	return ipPort
}

// hashIP anonimiza una IP con SHA-256 (cumplimiento GDPR/auditoría interna)
func hashIP(ip string) string {
	if ip == "" {
		return ""
	}
	h := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(h[:])
}

// isPrivateIP verifica si una IP pertenece a rangos privados/locales
func isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.", "192.168.",
		"172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
		"172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"127.", "169.254.", "0.0.0.0",
		"::1", "fc00:", "fe80:",
	}
	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

// extractCampaignData extrae fbclid de la URL y clasifica el origen del tráfico
func extractCampaignData(r *http.Request) (fbClickID, trafficSource string) {
	fbClickID = r.URL.Query().Get("fbclid")
	referer := r.Header.Get("Referer")
	switch {
	case strings.Contains(referer, "facebook.com") || strings.Contains(referer, "l.facebook.com") ||
		strings.Contains(referer, "fb.me") || strings.Contains(referer, "fb.com"):
		trafficSource = "facebook"
	case strings.Contains(referer, "instagram.com"):
		trafficSource = "instagram"
	case strings.Contains(referer, "twitter.com") || strings.Contains(referer, "t.co"):
		trafficSource = "twitter"
	case strings.Contains(referer, "tiktok.com"):
		trafficSource = "tiktok"
	case referer != "":
		host := referer
		if idx := strings.Index(host, "//"); idx != -1 {
			host = host[idx+2:]
		}
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		trafficSource = "other:" + host
	default:
		trafficSource = "direct"
	}
	return fbClickID, trafficSource
}

// checkSpamhausXBL consulta la lista ZEN de Spamhaus via DNS lookup
// Detecta IPs de botnets, malware y fuentes de spam conocidas
func checkSpamhausXBL(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "ipv6_skipped"
	}
	// Revertir octetos para la consulta DNS inversa
	reversed := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
	query := reversed + ".zen.spamhaus.org"

	addrs, err := net.LookupHost(query)
	if err != nil {
		// NXDOMAIN = IP no está en ninguna lista (clean)
		return "clean"
	}

	for _, addr := range addrs {
		switch addr {
		case "127.0.0.2":
			return "listed_sbl" // SBL: fuente directa de spam
		case "127.0.0.4":
			return "listed_xbl" // XBL: exploit/botnet/malware
		case "127.0.0.9":
			return "listed_sbl_css" // SBL CSS: botnet C&C
		case "127.0.0.10", "127.0.0.11":
			return "listed_pbl" // PBL: política de bloqueo
		default:
			if strings.HasPrefix(addr, "127.") {
				return "listed_other"
			}
		}
	}
	return "clean"
}

// getStringFromMap extrae un string de un mapa genérico de forma segura
func getStringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// trackAttackerProfile gestiona perfiles de atacantes por hardware fingerprint
// Si el mismo fingerprint aparece con múltiples IPs, es un atacante conocido
func trackAttackerProfile(fingerprint, ipHash, fbClickID string) (isKnown bool, groupID string) {
	if fingerprint == "" || fingerprint == "error" {
		return false, ""
	}

	profileMu.Lock()
	defer profileMu.Unlock()

	profile, exists := attackerProfiles[fingerprint]
	if !exists {
		profile = &AttackerProfile{
			Fingerprint: fingerprint,
			IPHashes:    []string{ipHash},
			FirstSeen:   time.Now().Format(time.RFC3339),
			LastSeen:    time.Now().Format(time.RFC3339),
			HitCount:    1,
			FBClickIDs:  []string{},
		}
		if fbClickID != "" {
			profile.FBClickIDs = append(profile.FBClickIDs, fbClickID)
		}
		attackerProfiles[fingerprint] = profile
		return false, fingerprint
	}

	// Perfil existente: actualizar datos
	profile.HitCount++
	profile.LastSeen = time.Now().Format(time.RFC3339)

	// Comprobar si es una IP nueva (posible rotación de VPN / multi-cuenta)
	ipSeen := false
	for _, h := range profile.IPHashes {
		if h == ipHash {
			ipSeen = true
			break
		}
	}
	if !ipSeen {
		profile.IPHashes = append(profile.IPHashes, ipHash)
		if len(profile.IPHashes) > 1 {
			isKnown = true // Mismo hardware, IPs distintas → alerta multi-cuenta
			log.Printf("🚨 MULTI-IP DETECTED: fingerprint=%s... IPs=%d",
				fingerprint[:min(len(fingerprint), 12)], len(profile.IPHashes))
		}
	}

	if fbClickID != "" {
		fbSeen := false
		for _, f := range profile.FBClickIDs {
			if f == fbClickID {
				fbSeen = true
				break
			}
		}
		if !fbSeen {
			profile.FBClickIDs = append(profile.FBClickIDs, fbClickID)
		}
	}

	return isKnown, fingerprint
}

// ═══════════════════════════════════════════════════════════════════════════
// SISTEMA DE AUTENTICACIÓN ADMIN (JWT + BAN por IP)
// ═══════════════════════════════════════════════════════════════════════════

// jwtMiddleware valida el Bearer Token en cada petición protegida
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"token requerido"}`, http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		secret := requireEnv("ADMIN_JWT_SECRET")

		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("método de firma inesperado")
			}
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, `{"error":"token inválido"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// jwtCookieMiddleware protege rutas HTML: valida cookie "bl_token" o header Bearer.
// Si no hay token válido redirige al inicio en vez de dar 401.
func jwtCookieMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := requireEnv("ADMIN_JWT_SECRET")
		tokenStr := ""

		// 1. Intentar cookie
		if c, err := r.Cookie("bl_token"); err == nil {
			tokenStr = c.Value
		}
		// 2. Fallback a Bearer header
		if tokenStr == "" {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				tokenStr = strings.TrimPrefix(h, "Bearer ")
			}
		}
		if tokenStr == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("método de firma inválido")
			}
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestHasValidAdminCredentials(r *http.Request) bool {
	if r == nil || r.Body == nil {
		return false
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	if err != nil || len(strings.TrimSpace(string(bodyBytes))) == 0 {
		return false
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(bodyBytes, &creds); err != nil {
		return false
	}

	adminUser := getEnv("ADMIN_USERNAME", "admin")
	adminPass := requireEnv("ADMIN_PASSWORD")
	return creds.Username == adminUser && creds.Password == adminPass
}

func clearAdminLoginBanRecords(ip string) {
	if ip == "" {
		return
	}

	var deleted []BanEntry
	_, err := supabaseClient.From("banned_ips").
		Delete("", "").
		Filter("ip", "eq", ip).
		Filter("reason", "ilike", "admin_login%").
		ExecuteTo(&deleted)
	if err != nil {
		log.Printf("⚠️ Error limpiando bans admin de %s: %v", ip, err)
	}
}

// banMiddleware bloquea IPs baneadas consultando Supabase.
// Filtra por razón que empiece con "admin_login_blocked" para solo banear por intentos de login.
func banMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := cleanIPPort(r.RemoteAddr)

		// Verificar si la IP tiene ban definitivo en Supabase
		var banned []BanEntry
		_, err := supabaseClient.From("banned_ips").Select("ip,reason", "", false).
			Filter("ip", "eq", ip).ExecuteTo(&banned)
		if err == nil {
			blockedByLogin := false
			for _, b := range banned {
				if strings.HasPrefix(b.Reason, "admin_login_blocked") {
					blockedByLogin = true
					break
				}
			}
			if blockedByLogin {
				if requestHasValidAdminCredentials(r) {
					log.Printf("🟡 IP con ban previo permitida por credenciales válidas: %s", ip)
				} else {
					log.Printf("🔴 IP CON BAN DE LOGIN intentó acceder: %s", ip)
					http.Error(w, `{"error":"IP bloqueada permanentemente"}`, http.StatusForbidden)
					return
				}
			}
		}
		// Sincronizar contador en memoria desde Supabase (intentos anteriores al reinicio)
		attemptCount := 0
		for _, b := range banned {
			if strings.HasPrefix(b.Reason, "admin_login_attempt_") {
				attemptCount++
			}
		}
		if attemptCount > 0 {
			loginAttemptsMu.Lock()
			if loginAttempts[ip] < attemptCount {
				loginAttempts[ip] = attemptCount
			}
			loginAttemptsMu.Unlock()
		}
		next(w, r)
	}
}

// loginHandler procesa el login del admin y emite un JWT
// El conteo de intentos es PERSISTENTE en Supabase: sobrevive reinicios del servidor.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	ip := cleanIPPort(r.RemoteAddr)

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, `{"error":"petición inválida"}`, http.StatusBadRequest)
		return
	}

	adminUser := getEnv("ADMIN_USERNAME", "admin")
	adminPass := requireEnv("ADMIN_PASSWORD")
	secret := requireEnv("ADMIN_JWT_SECRET")

	if creds.Username != adminUser || creds.Password != adminPass {
		// ── Contador en memoria (rápido) ──────────────────────────────────
		loginAttemptsMu.Lock()
		loginAttempts[ip]++
		attempts := loginAttempts[ip]
		loginAttemptsMu.Unlock()

		log.Printf("❌ Login fallido desde %s — intento %d/%d", ip, attempts, MAX_LOGIN_ATTEMPTS)

		// ── Persistir intento en Supabase (razón incremental) ─────────────
		go func(currentAttempts int) {
			if currentAttempts >= MAX_LOGIN_ATTEMPTS {
				// Ban definitivo persistente
				entry := BanEntry{
					IP:       ip,
					BannedAt: time.Now().Format(time.RFC3339),
					Reason:   fmt.Sprintf("admin_login_blocked_after_%d_attempts", currentAttempts),
				}
				var res []BanEntry
				if _, e := supabaseClient.From("banned_ips").Insert(entry, false, "", "", "").ExecuteTo(&res); e != nil {
					log.Printf("⚠️ Error baneando IP en Supabase: %v", e)
				} else {
					log.Printf("🔨 IP BANEADA DEFINITIVAMENTE EN SUPABASE: %s", ip)
				}
			} else {
				// Registrar intento fallido (no ban aún)
				attemptEntry := BanEntry{
					IP:       ip,
					BannedAt: time.Now().Format(time.RFC3339),
					Reason:   fmt.Sprintf("admin_login_attempt_%d_of_%d", currentAttempts, MAX_LOGIN_ATTEMPTS),
				}
				var res []BanEntry
				if _, e := supabaseClient.From("banned_ips").Insert(attemptEntry, false, "", "", "").ExecuteTo(&res); e != nil {
					log.Printf("⚠️ Error registrando intento en Supabase: %v", e)
				}
			}
		}(attempts)

		if attempts >= MAX_LOGIN_ATTEMPTS {
			log.Printf("🔨 IP BLOQUEADA POR INTENTOS: %s", ip)
			http.Error(w, `{"error":"IP bloqueada permanentemente por intentos excesivos"}`, http.StatusForbidden)
			return
		}

		http.Error(w, fmt.Sprintf(`{"error":"credenciales incorrectas","remaining":%d}`, MAX_LOGIN_ATTEMPTS-attempts), http.StatusUnauthorized)
		return
	}

	// Login exitoso — limpiar contador en memoria
	loginAttemptsMu.Lock()
	delete(loginAttempts, ip)
	loginAttemptsMu.Unlock()
	clearAdminLoginBanRecords(ip)

	// Generar JWT con expiración de 8 horas
	claims := jwt.MapClaims{
		"sub": adminUser,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(8 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		http.Error(w, `{"error":"error generando token"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Login exitoso desde %s", ip)

	// Establecer cookie HttpOnly para proteger /admin.html
	http.SetCookie(w, &http.Cookie{
		Name:     "bl_token",
		Value:    signed,
		Path:     "/",
		MaxAge:   8 * 3600,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": signed})
}

// getAttackers devuelve todos los perfiles de atacantes detectados
func getAttackers(w http.ResponseWriter, r *http.Request) {
	profileMu.RLock()
	defer profileMu.RUnlock()

	profiles := make([]*AttackerProfile, 0, len(attackerProfiles))
	for _, p := range attackerProfiles {
		profiles = append(profiles, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profiles)
}
func authHandler(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	decodedBytes, err := decodeTelemetryBody(bodyBytes)
	if err != nil {
		http.Error(w, "Invalid base64 data", http.StatusBadRequest)
		return
	}

	var payload AuthPayload
	if payload, err = normalizeTelemetryPayload(decodedBytes); err != nil {
		http.Error(w, "Failed to unmarshal payload", http.StatusBadRequest)
		return
	}
	hardwareHash := strings.TrimSpace(payload.HardwareHash)
	if hardwareHash == "" {
		hardwareHash = strings.TrimSpace(payload.Fingerprint)
	}
	if hardwareHash == "" {
		http.Error(w, "Missing hardware fingerprint", http.StatusBadRequest)
		return
	}
	connIP := cleanIPPort(r.RemoteAddr)
	realIP := strings.TrimSpace(payload.NetworkIP)
	if realIP == "" {
		realIP = extractPublicIPFromLocation(payload.Location)
	}
	fingerprintPreview := hardwareHash
	if len(fingerprintPreview) > 8 {
		fingerprintPreview = fingerprintPreview[:8]
	}

	// 3. Detección de Autofill en Honeypots (f-email, f-name)
	exfiltrationDetected := false
	if payload.UserData["f-email"] != "" || payload.UserData["f-name"] != "" {
		exfiltrationDetected = true
		log.Printf("⚠️ EXFILTRATION DETECTED: Honeypot fields filled (f-email: %s, f-name: %s)", payload.UserData["f-email"], payload.UserData["f-name"])
	}

	// 4. Inteligencia de Amenazas (Bypass de Proxy y Spamhaus)
	spamhausStatus := "clean"
	if realIP != "" && realIP != "unknown" {
		spamhausStatus = checkSpamhausXBL(realIP)
	}

	// 6. Preparar mapa para SUPABASE (Incluir flag y vulnerabilidades)
	updateData := map[string]interface{}{
		"hardware_fingerprint": hardwareHash,
		"email_capturado":      payload.UserData["email"],
		"nombre_real":          payload.UserData["name"],
		"telefono":             payload.UserData["phone"],
		"ip_real_webrtc":       realIP,
		"spamhaus_status":      spamhausStatus,
		"timestamp":            time.Now().Format(time.RFC3339),
		"pseudonimo":           payload.PlayerData["pseudonimo"],
		"fecha_inicio_rol":     payload.PlayerData["fechaInicioRol"],
		"avatar_url":           payload.PlayerData["avatarUrl"],
		"division":             payload.PlayerData["division"],
		"country_code":         payload.PlayerData["countryCode"],
		"primary_color":        payload.PlayerData["primaryColor"],
		"bio":                  payload.PlayerData["bio"],
	}
	if connIP != "" {
		updateData["ip_conexion_hash"] = hashIP(connIP)
	}
	if payload.SessionID != "" {
		updateData["fb_click_id"] = payload.SessionID
	}
	if userAgent := firstNonEmpty(normalizeNullableString(payload.FullTelemetry["userAgent"]), strings.TrimSpace(r.UserAgent())); userAgent != "" {
		updateData["user_agent"] = userAgent
	}
	// Guardar clave personal hasheada si se proporcionó
	if pk, ok := payload.PlayerData["playerKey"]; ok {
		if pkStr := strings.TrimSpace(fmt.Sprintf("%v", pk)); pkStr != "" && pkStr != "<nil>" {
			h := sha256.Sum256([]byte(pkStr))
			updateData["player_key_hash"] = hex.EncodeToString(h[:])
		}
	}
	blockedTelemetryFields := blockedTelemetryFieldNames(updateData)
	updateData = filterTelemetryAuditWriteData(updateData)
	telemetrySidecar, hasTelemetrySidecar := buildTelemetrySidecarPayload(payload)
	if len(blockedTelemetryFields) > 0 {
		log.Printf("🚨 TELEMETRY WRITE BLOCKED: fp=%s ip=%s real=%s fields=%s",
			compactAuditValue(fingerprintPreview, 12),
			compactAuditValue(connIP, 64),
			compactAuditValue(realIP, 64),
			strings.Join(blockedTelemetryFields, ","),
		)
	}

	// 7. Persistencia ASÍNCRONA con UPSERT
	go func() {
		if hasTelemetrySidecar {
			if err := persistTelemetrySidecar(hardwareHash, telemetrySidecar); err != nil {
				log.Printf("⚠️ Error persistiendo telemetry sidecar: %v", err)
			}
		}

		_, err := persistAuditLogIdentity(hardwareHash, updateData)
		if err != nil {
			log.Printf("⚠️ Error Upsert Supabase: %v", err)
		} else {
			log.Printf("🎯 [IDENTIDAD VINCULADA] FP: %s... | Email: %v | Exfiltration: %v", fingerprintPreview, payload.UserData["email"], exfiltrationDetected)
		}
	}()

	// 8. Respuesta al cliente
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "identity_linked"})
}

func decodeTelemetryBody(body []byte) ([]byte, error) {
	encoded := strings.TrimSpace(string(body))
	if encoded == "" {
		return nil, fmt.Errorf("empty telemetry body")
	}

	var requestBody struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(body, &requestBody); err == nil && strings.TrimSpace(requestBody.Data) != "" {
		encoded = strings.TrimSpace(requestBody.Data)
	} else {
		var rawString string
		if err := json.Unmarshal(body, &rawString); err == nil && strings.TrimSpace(rawString) != "" {
			encoded = strings.TrimSpace(rawString)
		}
	}

	return base64.StdEncoding.DecodeString(encoded)
}

func mergeTelemetryMap(dst *map[string]interface{}, src map[string]interface{}) {
	if len(src) == 0 {
		return
	}
	if *dst == nil {
		*dst = make(map[string]interface{}, len(src))
	}
	for key, value := range src {
		(*dst)[key] = value
	}
}

func appendTelemetryVulnerabilities(dst *[]map[string]interface{}, values []interface{}) {
	for _, value := range values {
		if item, ok := value.(map[string]interface{}); ok {
			*dst = append(*dst, item)
		}
	}
}

func extractPublicIPFromLocation(location map[string]interface{}) string {
	if len(location) == 0 {
		return ""
	}
	return normalizeNullableString(location["publicIP"])
}

func normalizeTelemetryPayload(decodedBytes []byte) (AuthPayload, error) {
	var payload AuthPayload
	if err := json.Unmarshal(decodedBytes, &payload); err == nil {
		hasDirectTelemetryData := payload.HardwareHash != "" || payload.Fingerprint != "" || len(payload.UserData) > 0 || len(payload.PlayerData) > 0 || len(payload.AdvancedFingerprint) > 0 || len(payload.UserBehavior) > 0 || len(payload.NetworkInfo) > 0 || len(payload.Location) > 0
		if hasDirectTelemetryData {
			if payload.NetworkIP == "" {
				payload.NetworkIP = extractPublicIPFromLocation(payload.Location)
			}
			return payload, nil
		}
	}

	var envelope telemetryEnvelope
	if err := json.Unmarshal(decodedBytes, &envelope); err != nil {
		return AuthPayload{}, err
	}
	if len(envelope.Data) == 0 {
		return AuthPayload{}, fmt.Errorf("empty telemetry envelope")
	}

	payload = AuthPayload{
		SessionID:           envelope.SessionID,
		UserData:            map[string]interface{}{},
		Location:            map[string]interface{}{},
		FullTelemetry:       map[string]interface{}{},
		PlayerData:          map[string]interface{}{},
		Vulnerabilities:     []map[string]interface{}{},
		AdvancedFingerprint: map[string]interface{}{},
		UserBehavior:        map[string]interface{}{},
		NetworkInfo:         map[string]interface{}{},
	}

	for _, item := range envelope.Data {
		if payload.SessionID == "" {
			payload.SessionID = normalizeNullableString(item["sessionID"])
			if payload.SessionID == "" {
				payload.SessionID = normalizeNullableString(item["sessionId"])
			}
		}
		if payload.HardwareHash == "" {
			payload.HardwareHash = normalizeNullableString(item["hardwareHash"])
		}
		if payload.Fingerprint == "" {
			payload.Fingerprint = normalizeNullableString(item["fingerprint"])
		}
		if payload.NetworkIP == "" {
			payload.NetworkIP = normalizeNullableString(item["networkIP"])
		}

		if userData, ok := item["userData"].(map[string]interface{}); ok {
			mergeTelemetryMap(&payload.UserData, userData)
		}
		if playerData, ok := item["playerData"].(map[string]interface{}); ok {
			mergeTelemetryMap(&payload.PlayerData, playerData)
		}
		if location, ok := item["location"].(map[string]interface{}); ok {
			mergeTelemetryMap(&payload.Location, location)
			if payload.NetworkIP == "" {
				payload.NetworkIP = extractPublicIPFromLocation(location)
			}
		}
		if fullTelemetry, ok := item["fullTelemetry"].(map[string]interface{}); ok {
			mergeTelemetryMap(&payload.FullTelemetry, fullTelemetry)
		}
		if advancedFingerprint, ok := item["advancedFingerprint"].(map[string]interface{}); ok {
			mergeTelemetryMap(&payload.AdvancedFingerprint, advancedFingerprint)
		}
		if userBehavior, ok := item["userBehavior"].(map[string]interface{}); ok {
			mergeTelemetryMap(&payload.UserBehavior, userBehavior)
		}
		if networkInfo, ok := item["networkInfo"].(map[string]interface{}); ok {
			mergeTelemetryMap(&payload.NetworkInfo, networkInfo)
		}
		if vulnerabilities, ok := item["vulnerabilities"].([]interface{}); ok {
			appendTelemetryVulnerabilities(&payload.Vulnerabilities, vulnerabilities)
		}
	}

	return payload, nil
}

type PublicPlayer struct {
	Pseudonimo      string `json:"pseudonimo"`
	AvatarURL       string `json:"avatar_url"`
	Division        string `json:"division"`
	FechaInicioRol  string `json:"fecha_inicio_rol"`
	Timestamp       string `json:"timestamp,omitempty"`
	Status          string `json:"status"`
	Wins            int    `json:"wins"`
	Losses          int    `json:"losses"`
	Draws           int    `json:"draws"`
	CurrentStreak   int    `json:"current_streak"`
	RankingPoints   int    `json:"ranking_points"`
	CountryCode     string `json:"country_code"`
	ClanName        string `json:"clan_name"`
	PrimaryColor    string `json:"primary_color"`
	Bio             string `json:"bio"`
	TopChar1        string `json:"top_char_1"`
	TopChar1Image   string `json:"top_char_1_image,omitempty"`
	TopChar2        string `json:"top_char_2"`
	TopChar2Image   string `json:"top_char_2_image,omitempty"`
	TopChar3        string `json:"top_char_3"`
	TopChar3Image   string `json:"top_char_3_image,omitempty"`
	PlayerProfileID string `json:"-"`
}

type characterSlot struct {
	Name  string
	Image string
}

type rosterAuditSnapshot struct {
	Pseudonimo     string
	Division       string
	FechaInicioRol string
	Timestamp      string
	CountryCode    string
	AvatarURL      string
	PrimaryColor   string
	Bio            string
}

func normalizeNullableString(value interface{}) string {
	text := strings.TrimSpace(fmt.Sprintf("%v", value))
	if text == "" || text == "<nil>" || strings.EqualFold(text, "null") {
		return ""
	}
	return text
}

func normalizedPseudoMatchKey(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	normalized := norm.NFKD.String(trimmed)
	var builder strings.Builder
	builder.Grow(len(normalized))
	for _, r := range strings.ToLower(normalized) {
		switch {
		case unicode.IsLetter(r) || unicode.IsNumber(r):
			builder.WriteRune(r)
		case r == ' ' || r == '_' || r == '-':
			continue
		default:
			if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r) {
				continue
			}
		}
	}
	return builder.String()
}

func sameNormalizedPseudo(left, right string) bool {
	leftKey := normalizedPseudoMatchKey(left)
	rightKey := normalizedPseudoMatchKey(right)
	if leftKey == "" || rightKey == "" {
		return false
	}
	return leftKey == rightKey
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = normalizeNullableString(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func isOfficialQualifiedStatus(status string) bool {
	trimmed := strings.ToLower(normalizeNullableString(status))
	return trimmed == "active" || strings.HasPrefix(trimmed, "competidor")
}

func officialQualifiedDivisionKey(division string) string {
	trimmed := strings.ToLower(normalizeNullableString(division))
	if strings.Contains(trimmed, "ciudad") {
		return "ciudad"
	}
	if strings.Contains(trimmed, "universal") {
		return "universal"
	}
	return ""
}

const (
	cityDivisionSlotCap      = 16
	universalDivisionSlotCap = 12
	reservedUniversalPseudo  = "Lucifer Vosgronne"
)

func divisionSlotCapForKey(divisionKey string) int {
	switch strings.ToLower(strings.TrimSpace(divisionKey)) {
	case "universal":
		return universalDivisionSlotCap
	case "ciudad":
		return cityDivisionSlotCap
	default:
		return cityDivisionSlotCap
	}
}

func divisionSlotCapForName(division string) int {
	return divisionSlotCapForKey(officialQualifiedDivisionKey(division))
}

func maxDivisionSlotCap() int {
	if cityDivisionSlotCap >= universalDivisionSlotCap {
		return cityDivisionSlotCap
	}
	return universalDivisionSlotCap
}

func ensureReservedUniversalCompetitor(players []PublicPlayer, limit int) []PublicPlayer {
	for _, player := range players {
		if strings.EqualFold(normalizeNullableString(player.Pseudonimo), reservedUniversalPseudo) {
			return players
		}
	}
	if limit > 0 && len(players) >= limit {
		return players
	}
	return append(players, PublicPlayer{
		Pseudonimo:   reservedUniversalPseudo,
		Division:     "Universal",
		Status:       "active",
		PrimaryColor: "#ff7440",
	})
}

func officialQualifiedPlayerKey(player PublicPlayer) string {
	if pseudonimo := strings.ToLower(normalizeNullableString(player.Pseudonimo)); pseudonimo != "" {
		return "pseudo:" + pseudonimo
	}
	if profileID := strings.ToLower(normalizeNullableString(player.PlayerProfileID)); profileID != "" {
		return "profile:" + profileID
	}
	return ""
}

func earlierOfficialTimestamp(left, right string) string {
	left = normalizeNullableString(left)
	right = normalizeNullableString(right)
	switch {
	case left == "":
		return right
	case right == "":
		return left
	case right < left:
		return right
	default:
		return left
	}
}

func shouldPreferOfficialQualifiedPlayer(current, candidate PublicPlayer) bool {
	currentProfileID := normalizeNullableString(current.PlayerProfileID)
	candidateProfileID := normalizeNullableString(candidate.PlayerProfileID)
	if currentProfileID == "" && candidateProfileID != "" {
		return true
	}
	if currentProfileID != "" && candidateProfileID == "" {
		return false
	}
	currentTimestamp := normalizeNullableString(current.Timestamp)
	candidateTimestamp := normalizeNullableString(candidate.Timestamp)
	if currentTimestamp == "" && candidateTimestamp != "" {
		return true
	}
	if currentTimestamp != "" && candidateTimestamp == "" {
		return false
	}
	if normalizeNullableString(current.Division) == "" && normalizeNullableString(candidate.Division) != "" {
		return true
	}
	if normalizeNullableString(current.AvatarURL) == "" && normalizeNullableString(candidate.AvatarURL) != "" {
		return true
	}
	if candidate.RankingPoints != current.RankingPoints {
		return candidate.RankingPoints > current.RankingPoints
	}
	if candidate.Wins != current.Wins {
		return candidate.Wins > current.Wins
	}
	return false
}

func mergeOfficialQualifiedPlayer(current, candidate PublicPlayer) PublicPlayer {
	if shouldPreferOfficialQualifiedPlayer(current, candidate) {
		current, candidate = candidate, current
	}
	current.Pseudonimo = firstNonEmpty(current.Pseudonimo, candidate.Pseudonimo)
	current.AvatarURL = firstNonEmpty(current.AvatarURL, candidate.AvatarURL)
	current.Division = firstNonEmpty(current.Division, candidate.Division)
	current.FechaInicioRol = firstNonEmpty(current.FechaInicioRol, candidate.FechaInicioRol)
	current.Timestamp = earlierOfficialTimestamp(current.Timestamp, candidate.Timestamp)
	current.Status = firstNonEmpty(current.Status, candidate.Status)
	current.CountryCode = firstNonEmpty(current.CountryCode, candidate.CountryCode)
	current.ClanName = firstNonEmpty(current.ClanName, candidate.ClanName)
	current.PrimaryColor = firstNonEmpty(current.PrimaryColor, candidate.PrimaryColor)
	current.Bio = firstNonEmpty(current.Bio, candidate.Bio)
	current.TopChar1 = firstNonEmpty(current.TopChar1, candidate.TopChar1)
	current.TopChar1Image = firstNonEmpty(current.TopChar1Image, candidate.TopChar1Image)
	current.TopChar2 = firstNonEmpty(current.TopChar2, candidate.TopChar2)
	current.TopChar2Image = firstNonEmpty(current.TopChar2Image, candidate.TopChar2Image)
	current.TopChar3 = firstNonEmpty(current.TopChar3, candidate.TopChar3)
	current.TopChar3Image = firstNonEmpty(current.TopChar3Image, candidate.TopChar3Image)
	current.PlayerProfileID = firstNonEmpty(current.PlayerProfileID, candidate.PlayerProfileID)
	return current
}

func isValidHexColor(s string) bool {
	if len(s) != 6 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isValidCountryCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for _, c := range s {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func isAllowedCharacterImageURL(raw string) bool {
	text := strings.TrimSpace(raw)
	if text == "" {
		return true
	}
	parsed, err := url.Parse(text)
	if err != nil {
		return false
	}
	if parsed.Host == "" {
		if parsed.Scheme != "" {
			return false
		}
		return strings.HasPrefix(parsed.Path, "/uploads/") && !strings.Contains(parsed.Path, "..") && !strings.Contains(parsed.Path, `\\`)
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

func decodeCharacterSlot(raw string) characterSlot {
	text := normalizeNullableString(raw)
	if text == "" {
		return characterSlot{}
	}
	parts := strings.SplitN(text, "\n", 2)
	if len(parts) == 2 {
		name := strings.TrimSpace(parts[0])
		image := strings.TrimSpace(parts[1])
		if image != "" && isAllowedCharacterImageURL(image) {
			return characterSlot{Name: name, Image: image}
		}
	}
	return characterSlot{Name: text}
}

func encodeCharacterSlot(name, image string) string {
	trimmedName := strings.TrimSpace(name)
	trimmedImage := strings.TrimSpace(image)
	if trimmedName == "" && trimmedImage == "" {
		return ""
	}
	if trimmedImage == "" {
		return trimmedName
	}
	return trimmedName + "\n" + trimmedImage
}

func filterTelemetryAuditWriteData(values map[string]interface{}) map[string]interface{} {
	filtered := make(map[string]interface{}, len(values))
	for key, value := range values {
		if _, ok := telemetryAuditWritableColumns[key]; !ok {
			continue
		}
		filtered[key] = value
	}
	return filtered
}

func persistAuditLogIdentity(hardwareFingerprint string, updateData map[string]interface{}) (interface{}, error) {
	trimmedFingerprint := strings.TrimSpace(hardwareFingerprint)
	if trimmedFingerprint == "" {
		return nil, fmt.Errorf("empty hardware fingerprint")
	}

	var existingRows []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").
		Select("id", "", false).
		Filter("hardware_fingerprint", "eq", trimmedFingerprint).
		Order("timestamp", &postgrest.OrderOpts{Ascending: false}).
		Limit(1, "").
		ExecuteTo(&existingRows)
	if err != nil {
		return nil, err
	}

	if len(existingRows) > 0 {
		auditID := existingRows[0]["id"]
		_, _, err = supabaseClient.From("audit_logs").
			Update(updateData, "", "").
			Filter("id", "eq", fmt.Sprintf("%v", auditID)).
			Execute()
		if err != nil {
			return nil, err
		}
		if _, linkErr := syncCompetitiveProfileAuditLink(fmt.Sprintf("%v", auditID), normalizeNullableString(updateData["pseudonimo"]), trimmedFingerprint); linkErr != nil {
			log.Printf("⚠️ Error sync player_competitive_profiles: %v", linkErr)
		}
		return auditID, nil
	}

	var insertedRows []map[string]interface{}
	_, err = supabaseClient.From("audit_logs").
		Insert(updateData, false, "", "", "").
		ExecuteTo(&insertedRows)
	if err != nil {
		return nil, err
	}
	if len(insertedRows) == 0 {
		return nil, nil
	}
	auditID := insertedRows[0]["id"]
	if _, linkErr := syncCompetitiveProfileAuditLink(fmt.Sprintf("%v", auditID), normalizeNullableString(updateData["pseudonimo"]), trimmedFingerprint); linkErr != nil {
		log.Printf("⚠️ Error sync player_competitive_profiles: %v", linkErr)
	}
	return auditID, nil
}

func isTelemetrySidecarNotFound(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(message, `"error":"not_found"`) || strings.Contains(message, `"message":"object not found"`) || strings.Contains(message, "statuscode\":\"404")
}

func buildTelemetrySidecarPayload(payload AuthPayload) (telemetrySidecarPayload, bool) {
	sidecar := telemetrySidecarPayload{
		AdvancedFingerprint: payload.AdvancedFingerprint,
		UserBehavior:        payload.UserBehavior,
		NetworkInfo:         payload.NetworkInfo,
		Vulnerabilities:     payload.Vulnerabilities,
		UpdatedAt:           time.Now().Format(time.RFC3339),
	}
	if len(sidecar.AdvancedFingerprint) == 0 && len(sidecar.UserBehavior) == 0 && len(sidecar.NetworkInfo) == 0 && len(sidecar.Vulnerabilities) == 0 {
		return telemetrySidecarPayload{}, false
	}
	return sidecar, true
}

func getTelemetrySidecarCache(hardwareFingerprint string) (telemetrySidecarPayload, bool) {
	cacheKey := strings.TrimSpace(hardwareFingerprint)
	if cacheKey == "" {
		return telemetrySidecarPayload{}, false
	}
	rawEntry, ok := telemetrySidecarCache.Load(cacheKey)
	if !ok {
		return telemetrySidecarPayload{}, false
	}
	entry, ok := rawEntry.(telemetrySidecarCacheEntry)
	if !ok || time.Now().After(entry.ExpiresAt) {
		telemetrySidecarCache.Delete(cacheKey)
		return telemetrySidecarPayload{}, false
	}
	return entry.Data, true
}

func cacheTelemetrySidecar(hardwareFingerprint string, sidecar telemetrySidecarPayload) {
	cacheKey := strings.TrimSpace(hardwareFingerprint)
	if cacheKey == "" {
		return
	}
	telemetrySidecarCache.Store(cacheKey, telemetrySidecarCacheEntry{
		Data:      sidecar,
		ExpiresAt: time.Now().Add(2 * time.Minute),
	})
}

func telemetrySidecarDigest(hardwareFingerprint string) string {
	trimmedFingerprint := strings.TrimSpace(hardwareFingerprint)
	if trimmedFingerprint == "" {
		return ""
	}
	secret := strings.TrimSpace(getEnv("ADMIN_JWT_SECRET", ""))
	sum := sha256.Sum256([]byte("telemetry\n" + secret + "\n" + trimmedFingerprint))
	return hex.EncodeToString(sum[:])
}

func buildTelemetrySidecarObjectPath(hardwareFingerprint string) string {
	digest := telemetrySidecarDigest(hardwareFingerprint)
	if digest == "" {
		return ""
	}
	return buildStorageObjectPath("telemetry/" + digest + ".json")
}

func persistTelemetrySidecar(hardwareFingerprint string, sidecar telemetrySidecarPayload) error {
	trimmedFingerprint := strings.TrimSpace(hardwareFingerprint)
	if trimmedFingerprint == "" {
		return fmt.Errorf("empty telemetry sidecar fingerprint")
	}
	body, err := json.Marshal(sidecar)
	if err != nil {
		return err
	}
	if storageUploadsEnabled() {
		objectPath := buildTelemetrySidecarObjectPath(trimmedFingerprint)
		if objectPath == "" {
			return fmt.Errorf("empty telemetry sidecar object path")
		}
		if err := uploadBytesToSupabaseStorageObject(objectPath, "application/json", body, true); err != nil {
			return err
		}
	} else {
		if err := writeLocalTelemetrySidecar(trimmedFingerprint, body); err != nil {
			return err
		}
	}
	cacheTelemetrySidecar(trimmedFingerprint, sidecar)
	return nil
}

func loadTelemetrySidecar(hardwareFingerprint string) (telemetrySidecarPayload, bool) {
	trimmedFingerprint := strings.TrimSpace(hardwareFingerprint)
	if trimmedFingerprint == "" {
		return telemetrySidecarPayload{}, false
	}
	if cached, ok := getTelemetrySidecarCache(trimmedFingerprint); ok {
		return cached, true
	}

	var (
		body []byte
		err  error
	)
	if storageUploadsEnabled() {
		body, err = downloadSupabaseStorageObject(buildTelemetrySidecarObjectPath(trimmedFingerprint))
	} else {
		body, err = readLocalTelemetrySidecar(trimmedFingerprint)
	}
	if err != nil {
		if os.IsNotExist(err) {
			return telemetrySidecarPayload{}, false
		}
		if isTelemetrySidecarNotFound(err) {
			return telemetrySidecarPayload{}, false
		}
		preview := trimmedFingerprint
		if len(preview) > 8 {
			preview = preview[:8]
		}
		log.Printf("⚠️ telemetry sidecar read: fp=%s... err=%v", preview, err)
		return telemetrySidecarPayload{}, false
	}

	var sidecar telemetrySidecarPayload
	if err := json.Unmarshal(body, &sidecar); err != nil {
		preview := trimmedFingerprint
		if len(preview) > 8 {
			preview = preview[:8]
		}
		log.Printf("⚠️ telemetry sidecar decode: fp=%s... err=%v", preview, err)
		return telemetrySidecarPayload{}, false
	}
	cacheTelemetrySidecar(trimmedFingerprint, sidecar)
	return sidecar, true
}

func hasTelemetryMapValue(value interface{}) bool {
	telemetryMap, ok := value.(map[string]interface{})
	return ok && len(telemetryMap) > 0
}

func hasTelemetrySliceValue(value interface{}) bool {
	switch typed := value.(type) {
	case []interface{}:
		return len(typed) > 0
	case []map[string]interface{}:
		return len(typed) > 0
	default:
		return false
	}
}

func mergeVisitorTelemetrySidecar(row map[string]interface{}, sidecar telemetrySidecarPayload) {
	if len(sidecar.AdvancedFingerprint) > 0 && !hasTelemetryMapValue(row["advanced_fingerprint"]) {
		row["advanced_fingerprint"] = sidecar.AdvancedFingerprint
	}
	if len(sidecar.UserBehavior) > 0 && !hasTelemetryMapValue(row["user_behavior"]) {
		row["user_behavior"] = sidecar.UserBehavior
	}
	if len(sidecar.NetworkInfo) > 0 && !hasTelemetryMapValue(row["network_info"]) {
		row["network_info"] = sidecar.NetworkInfo
	}
	if len(sidecar.Vulnerabilities) > 0 && !hasTelemetrySliceValue(row["vulnerabilities"]) {
		row["vulnerabilities"] = sidecar.Vulnerabilities
	}
}

func enrichVisitorResultsWithTelemetry(results []map[string]interface{}) {
	uniqueFingerprints := make(map[string]struct{})
	for _, row := range results {
		hardwareFingerprint := normalizeNullableString(row["hardware_fingerprint"])
		if hardwareFingerprint == "" {
			continue
		}
		if hasTelemetryMapValue(row["advanced_fingerprint"]) && hasTelemetryMapValue(row["user_behavior"]) && hasTelemetryMapValue(row["network_info"]) && hasTelemetrySliceValue(row["vulnerabilities"]) {
			continue
		}
		uniqueFingerprints[hardwareFingerprint] = struct{}{}
	}
	if len(uniqueFingerprints) == 0 {
		return
	}

	sidecars := make(map[string]telemetrySidecarPayload, len(uniqueFingerprints))
	var sidecarsMu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 8)

	for hardwareFingerprint := range uniqueFingerprints {
		wg.Add(1)
		go func(fingerprint string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			sidecar, ok := loadTelemetrySidecar(fingerprint)
			if !ok {
				return
			}
			sidecarsMu.Lock()
			sidecars[fingerprint] = sidecar
			sidecarsMu.Unlock()
		}(hardwareFingerprint)
	}
	wg.Wait()

	for _, row := range results {
		hardwareFingerprint := normalizeNullableString(row["hardware_fingerprint"])
		sidecar, ok := sidecars[hardwareFingerprint]
		if !ok {
			continue
		}
		mergeVisitorTelemetrySidecar(row, sidecar)
	}
}

func loadPublicPlayers() ([]PublicPlayer, error) {
	var rows []map[string]interface{}
	_, err := supabaseClient.From("v_current_roster").
		Select("pseudonimo,avatar_url,division_name,fecha_inicio_rol,status,wins,losses,draws,current_streak,ranking_points,country_code,clan_name,primary_color,bio,player_profile_id", "", false).
		ExecuteTo(&rows)
	if err != nil {
		return nil, err
	}

	players := make([]PublicPlayer, 0, len(rows))
	for _, row := range rows {
		p := PublicPlayer{
			Pseudonimo:      normalizeNullableString(row["pseudonimo"]),
			AvatarURL:       normalizeNullableString(row["avatar_url"]),
			Division:        normalizeNullableString(row["division_name"]),
			FechaInicioRol:  normalizeNullableString(row["fecha_inicio_rol"]),
			Timestamp:       "",
			Status:          normalizeNullableString(row["status"]),
			CountryCode:     normalizeNullableString(row["country_code"]),
			ClanName:        normalizeNullableString(row["clan_name"]),
			PrimaryColor:    normalizeNullableString(row["primary_color"]),
			Bio:             normalizeNullableString(row["bio"]),
			PlayerProfileID: normalizeNullableString(row["player_profile_id"]),
		}
		if v, ok := row["wins"].(float64); ok {
			p.Wins = int(v)
		}
		if v, ok := row["losses"].(float64); ok {
			p.Losses = int(v)
		}
		if v, ok := row["draws"].(float64); ok {
			p.Draws = int(v)
		}
		if v, ok := row["current_streak"].(float64); ok {
			p.CurrentStreak = int(v)
		}
		if v, ok := row["ranking_points"].(float64); ok {
			p.RankingPoints = int(v)
		}
		if p.Pseudonimo == "" {
			continue
		}
		players = append(players, p)
	}

	var profileRows []map[string]interface{}
	_, profileErr := supabaseClient.From("player_competitive_profiles").
		Select("id,source_audit_log_id,top_char_1,top_char_2,top_char_3", "", false).
		ExecuteTo(&profileRows)
	if profileErr != nil {
		return nil, profileErr
	}
	profileIDToAuditID := make(map[string]string, len(profileRows))
	profileIDToChars := make(map[string][3]characterSlot, len(profileRows))
	for _, row := range profileRows {
		profileID := normalizeNullableString(row["id"])
		if profileID == "" {
			continue
		}
		profileIDToAuditID[profileID] = normalizeNullableString(row["source_audit_log_id"])
		profileIDToChars[profileID] = [3]characterSlot{
			decodeCharacterSlot(normalizeNullableString(row["top_char_1"])),
			decodeCharacterSlot(normalizeNullableString(row["top_char_2"])),
			decodeCharacterSlot(normalizeNullableString(row["top_char_3"])),
		}
	}

	var auditLogRows []map[string]interface{}
	_, auditErr := supabaseClient.From("audit_logs").
		Select("id,pseudonimo,division,fecha_inicio_rol,timestamp,country_code,avatar_url,primary_color,bio", "", false).
		Order("id", &postgrest.OrderOpts{Ascending: true}).
		ExecuteTo(&auditLogRows)
	if auditErr != nil {
		return nil, auditErr
	}
	auditByID := make(map[string]rosterAuditSnapshot, len(auditLogRows))
	latestAuditByPseudo := make(map[string]rosterAuditSnapshot, len(auditLogRows))
	for _, row := range auditLogRows {
		id := normalizeNullableString(row["id"])
		if id == "" {
			continue
		}
		snapshot := rosterAuditSnapshot{
			Pseudonimo:     normalizeNullableString(row["pseudonimo"]),
			Division:       normalizeNullableString(row["division"]),
			FechaInicioRol: normalizeNullableString(row["fecha_inicio_rol"]),
			Timestamp:      normalizeNullableString(row["timestamp"]),
			CountryCode:    normalizeNullableString(row["country_code"]),
			AvatarURL:      normalizeNullableString(row["avatar_url"]),
			PrimaryColor:   normalizeNullableString(row["primary_color"]),
			Bio:            normalizeNullableString(row["bio"]),
		}
		auditByID[id] = snapshot
		if pseudoKey := normalizeIdentityKey(snapshot.Pseudonimo); pseudoKey != "" {
			latestAuditByPseudo[pseudoKey] = snapshot
		}
	}

	for i := range players {
		pseudoKey := normalizeIdentityKey(players[i].Pseudonimo)
		profileID := players[i].PlayerProfileID
		if profileID == "" {
			if latestAudit, ok := latestAuditByPseudo[pseudoKey]; ok {
				players[i].AvatarURL = firstNonEmpty(latestAudit.AvatarURL, players[i].AvatarURL)
				players[i].CountryCode = firstNonEmpty(latestAudit.CountryCode, players[i].CountryCode)
				players[i].PrimaryColor = firstNonEmpty(latestAudit.PrimaryColor, players[i].PrimaryColor)
				players[i].Bio = firstNonEmpty(latestAudit.Bio, players[i].Bio)
			}
			avatar := firstUsableAlbumImageSource(players[i].AvatarURL, players[i].TopChar1Image, players[i].TopChar2Image, players[i].TopChar3Image)
			players[i].AvatarURL = avatar
			players[i].TopChar1Image = firstUsableAlbumImageSource(players[i].TopChar1Image, avatar, players[i].TopChar2Image, players[i].TopChar3Image)
			players[i].TopChar2Image = firstUsableAlbumImageSource(players[i].TopChar2Image, avatar, players[i].TopChar1Image, players[i].TopChar3Image)
			players[i].TopChar3Image = firstUsableAlbumImageSource(players[i].TopChar3Image, avatar, players[i].TopChar1Image, players[i].TopChar2Image)
			continue
		}
		if chars, ok := profileIDToChars[profileID]; ok {
			players[i].TopChar1 = chars[0].Name
			players[i].TopChar1Image = chars[0].Image
			players[i].TopChar2 = chars[1].Name
			players[i].TopChar2Image = chars[1].Image
			players[i].TopChar3 = chars[2].Name
			players[i].TopChar3Image = chars[2].Image
		}
		auditID := profileIDToAuditID[profileID]
		audit, ok := auditByID[auditID]
		if !ok {
			continue
		}
		players[i].Pseudonimo = firstNonEmpty(audit.Pseudonimo, players[i].Pseudonimo)
		players[i].Division = firstNonEmpty(audit.Division, players[i].Division)
		players[i].FechaInicioRol = firstNonEmpty(audit.FechaInicioRol, players[i].FechaInicioRol)
		players[i].Timestamp = firstNonEmpty(audit.Timestamp, players[i].Timestamp)
		players[i].CountryCode = firstNonEmpty(audit.CountryCode, players[i].CountryCode)
		players[i].AvatarURL = firstNonEmpty(audit.AvatarURL, players[i].AvatarURL)
		players[i].PrimaryColor = firstNonEmpty(audit.PrimaryColor, players[i].PrimaryColor)
		players[i].Bio = firstNonEmpty(audit.Bio, players[i].Bio)
		if latestAudit, ok := latestAuditByPseudo[pseudoKey]; ok {
			players[i].AvatarURL = firstNonEmpty(latestAudit.AvatarURL, players[i].AvatarURL)
			players[i].CountryCode = firstNonEmpty(latestAudit.CountryCode, players[i].CountryCode)
			players[i].PrimaryColor = firstNonEmpty(latestAudit.PrimaryColor, players[i].PrimaryColor)
			players[i].Bio = firstNonEmpty(latestAudit.Bio, players[i].Bio)
		}

		avatar := firstUsableAlbumImageSource(players[i].AvatarURL, players[i].TopChar1Image, players[i].TopChar2Image, players[i].TopChar3Image)
		players[i].AvatarURL = avatar
		players[i].TopChar1Image = firstUsableAlbumImageSource(players[i].TopChar1Image, avatar, players[i].TopChar2Image, players[i].TopChar3Image)
		players[i].TopChar2Image = firstUsableAlbumImageSource(players[i].TopChar2Image, avatar, players[i].TopChar1Image, players[i].TopChar3Image)
		players[i].TopChar3Image = firstUsableAlbumImageSource(players[i].TopChar3Image, avatar, players[i].TopChar1Image, players[i].TopChar2Image)
	}

	sort.SliceStable(players, func(i, j int) bool {
		if players[i].RankingPoints != players[j].RankingPoints {
			return players[i].RankingPoints > players[j].RankingPoints
		}
		if players[i].Wins != players[j].Wins {
			return players[i].Wins > players[j].Wins
		}
		return strings.ToLower(players[i].Pseudonimo) < strings.ToLower(players[j].Pseudonimo)
	})

	return players, nil
}

func officialQualifiedPlayersByDivision(players []PublicPlayer, limit int) map[string][]PublicPlayer {
	if limit <= 0 {
		limit = maxDivisionSlotCap()
	}
	grouped := map[string][]PublicPlayer{
		"ciudad":    {},
		"universal": {},
	}
	deduped := make(map[string]PublicPlayer, len(players))
	orderedKeys := make([]string, 0, len(players))
	for _, player := range players {
		if !isOfficialQualifiedStatus(player.Status) {
			continue
		}
		if officialQualifiedDivisionKey(player.Division) == "" {
			continue
		}
		identity := officialQualifiedPlayerKey(player)
		if identity == "" {
			continue
		}
		if current, exists := deduped[identity]; exists {
			deduped[identity] = mergeOfficialQualifiedPlayer(current, player)
			continue
		}
		deduped[identity] = player
		orderedKeys = append(orderedKeys, identity)
	}

	for _, identity := range orderedKeys {
		player := deduped[identity]
		divisionKey := officialQualifiedDivisionKey(player.Division)
		if divisionKey == "" {
			continue
		}
		grouped[divisionKey] = append(grouped[divisionKey], player)
	}

	for key := range grouped {
		sort.SliceStable(grouped[key], func(i, j int) bool {
			leftTs := normalizeNullableString(grouped[key][i].Timestamp)
			rightTs := normalizeNullableString(grouped[key][j].Timestamp)
			if leftTs != rightTs {
				return leftTs < rightTs
			}
			return strings.ToLower(grouped[key][i].Pseudonimo) < strings.ToLower(grouped[key][j].Pseudonimo)
		})
		effectiveLimit := limit
		if divisionCap := divisionSlotCapForKey(key); divisionCap > 0 && divisionCap < effectiveLimit {
			effectiveLimit = divisionCap
		}
		if key == "universal" {
			grouped[key] = ensureReservedUniversalCompetitor(grouped[key], effectiveLimit)
		}
		if len(grouped[key]) > effectiveLimit {
			grouped[key] = grouped[key][:effectiveLimit]
		}
	}

	return grouped
}

func officialQualifiedPlayersHandler(w http.ResponseWriter, r *http.Request) {
	players, err := loadPublicPlayers()
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	qualified := officialQualifiedPlayersByDivision(players, 16)
	resp := map[string]interface{}{
		"ciudad":        qualified["ciudad"],
		"universal":     qualified["universal"],
		"max":           maxDivisionSlotCap(),
		"ciudad_max":    divisionSlotCapForKey("ciudad"),
		"universal_max": divisionSlotCapForKey("universal"),
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(resp)
}

// publicCompetidoresHandler devuelve roster público con estadísticas competitivas
func publicCompetidoresHandler(w http.ResponseWriter, r *http.Request) {
	players, err := loadPublicPlayers()
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(players)
}

// ── GET /api/stats ─────────────────────────────────────────────────────────
// Devuelve estadísticas agregadas de la liga (total, por división).
func publicStatsHandler(w http.ResponseWriter, r *http.Request) {
	players, err := loadPublicPlayers()
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	totals := map[string]int{}
	total := 0
	for _, player := range players {
		if normalizeNullableString(player.Pseudonimo) == "" {
			continue
		}
		total++
		divisionName := normalizeNullableString(player.Division)
		if divisionName == "" {
			divisionName = "sin_division"
		}
		totals[divisionName]++
	}
	resp := map[string]int{"total": total}
	for divisionName, count := range totals {
		resp[divisionName] = count
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(resp)
}

func countDivisionCompetitors() (int, int, error) {
	players, err := loadPublicPlayers()
	if err != nil {
		return 0, 0, err
	}
	qualified := officialQualifiedPlayersByDivision(players, 16)
	return len(qualified["ciudad"]), len(qualified["universal"]), nil
}

// ── GET /api/rankings ────────────────────────────────────────────────────────
// Ranking actual por división. Acepta ?division=nombre para filtrar.
func tournamentRankingsHandler(w http.ResponseWriter, r *http.Request) {
	var results []map[string]interface{}
	q := supabaseClient.From("v_current_rankings").
		Select("division_name,player_profile_id,pseudonimo,avatar_url,ranking_position,ranking_points,wins,losses,draws,current_streak", "", false).
		Order("division_name", &postgrest.OrderOpts{Ascending: true})
	if div := r.URL.Query().Get("division"); div != "" {
		q = q.Filter("division_name", "eq", div)
	}
	_, err := q.ExecuteTo(&results)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// ── GET /api/champions ────────────────────────────────────────────────────────
// Campeones actuales por título/división.
func tournamentChampionsHandler(w http.ResponseWriter, r *http.Request) {
	var results []map[string]interface{}
	_, err := supabaseClient.From("v_current_champions").
		Select("title_name,division_name,pseudonimo,avatar_url,started_at,successful_defenses", "", false).
		ExecuteTo(&results)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// ── GET /api/fights ───────────────────────────────────────────────────────────
// Historial de peleas. Acepta ?division_id=N y ?limit=N (default 50, max 200).
// ── GET /api/combates?pseudo=... ───────────────────────────────────────────
// Devuelve el historial de combates de un competidor específico.
const completedFightNotesPrefix = "__bellator_completed__"

type completedFightMeta struct {
	State       string `json:"state"`
	Result      string `json:"result"`
	Player1Char string `json:"player1_char,omitempty"`
	Player2Char string `json:"player2_char,omitempty"`
	Notes       string `json:"notes,omitempty"`
	RecordedAt  string `json:"recorded_at,omitempty"`
}

type MatchRecord struct {
	ID            string `json:"id"`
	EventName     string `json:"event_name"`
	EventDate     string `json:"event_date"`
	Player1Pseudo string `json:"player1_pseudo"`
	Player2Pseudo string `json:"player2_pseudo"`
	Player1Avatar string `json:"player1_avatar"`
	Player2Avatar string `json:"player2_avatar"`
	Result        string `json:"result"`
	Player1Char   string `json:"player1_char"`
	Player2Char   string `json:"player2_char"`
	Division      string `json:"division"`
	Notes         string `json:"notes"`
	EventDateFmt  string `json:"event_date_fmt"`
}

func matchRecordID(value interface{}) string {
	if idFloat, ok := value.(float64); ok {
		return strconv.FormatInt(int64(idFloat), 10)
	}
	if idFloat, ok := value.(float32); ok {
		return strconv.FormatInt(int64(idFloat), 10)
	}
	if idInt, ok := value.(int); ok {
		return strconv.Itoa(idInt)
	}
	if idInt, ok := value.(int64); ok {
		return strconv.FormatInt(idInt, 10)
	}
	if idInt, ok := value.(int32); ok {
		return strconv.FormatInt(int64(idInt), 10)
	}
	if idNumber, ok := value.(json.Number); ok {
		return strings.TrimSpace(idNumber.String())
	}
	if text := normalizeNullableString(value); text != "" {
		return text
	}
	return ""
}

func finalizeMatchRecord(rec MatchRecord) MatchRecord {
	if t, err := time.Parse("2006-01-02", rec.EventDate); err == nil {
		rec.EventDateFmt = t.Format("02 Jan 2006")
	} else {
		rec.EventDateFmt = rec.EventDate
	}
	return rec
}

func matchRecordFromHistoryRow(row map[string]interface{}) MatchRecord {
	return finalizeMatchRecord(MatchRecord{
		ID:            matchRecordID(row["id"]),
		EventName:     normalizeNullableString(row["event_name"]),
		EventDate:     normalizeNullableString(row["event_date"]),
		Player1Pseudo: normalizeNullableString(row["player1_pseudo"]),
		Player2Pseudo: normalizeNullableString(row["player2_pseudo"]),
		Player1Avatar: normalizeNullableString(row["player1_avatar"]),
		Player2Avatar: normalizeNullableString(row["player2_avatar"]),
		Result:        normalizeNullableString(row["result"]),
		Player1Char:   normalizeNullableString(row["player1_char"]),
		Player2Char:   normalizeNullableString(row["player2_char"]),
		Division:      normalizeNullableString(row["division"]),
		Notes:         normalizeNullableString(row["notes"]),
	})
}

func sortMatchRecordsDesc(records []MatchRecord) {
	for i := 0; i < len(records); i++ {
		for j := i + 1; j < len(records); j++ {
			if records[j].EventDate > records[i].EventDate {
				records[i], records[j] = records[j], records[i]
			}
		}
	}
}

func encodeCompletedFightNotes(result, player1Char, player2Char, notes string) string {
	meta := completedFightMeta{
		State:       "completed",
		Result:      strings.TrimSpace(result),
		Player1Char: strings.TrimSpace(player1Char),
		Player2Char: strings.TrimSpace(player2Char),
		Notes:       strings.TrimSpace(notes),
		RecordedAt:  time.Now().Format(time.RFC3339),
	}
	body, err := json.Marshal(meta)
	if err != nil {
		return completedFightNotesPrefix + `{"state":"completed","result":"draw"}`
	}
	return completedFightNotesPrefix + string(body)
}

func decodeCompletedFightNotes(raw string) (completedFightMeta, bool) {
	text := strings.TrimSpace(raw)
	if !strings.HasPrefix(text, completedFightNotesPrefix) {
		return completedFightMeta{}, false
	}
	payload := strings.TrimSpace(strings.TrimPrefix(text, completedFightNotesPrefix))
	if payload == "" {
		return completedFightMeta{}, false
	}
	var meta completedFightMeta
	if err := json.Unmarshal([]byte(payload), &meta); err != nil {
		return completedFightMeta{}, false
	}
	meta.State = strings.ToLower(strings.TrimSpace(meta.State))
	meta.Result = strings.TrimSpace(meta.Result)
	meta.Player1Char = strings.TrimSpace(meta.Player1Char)
	meta.Player2Char = strings.TrimSpace(meta.Player2Char)
	meta.Notes = strings.TrimSpace(meta.Notes)
	if meta.State != "completed" {
		return completedFightMeta{}, false
	}
	if meta.Result != "player1" && meta.Result != "player2" && meta.Result != "draw" {
		return completedFightMeta{}, false
	}
	return meta, true
}

func isCompletedFightRow(rawNotes interface{}) bool {
	_, ok := decodeCompletedFightNotes(normalizeNullableString(rawNotes))
	return ok
}

func matchRecordFromUpcomingFightRow(row map[string]interface{}) (MatchRecord, bool) {
	meta, ok := decodeCompletedFightNotes(normalizeNullableString(row["notes"]))
	if !ok {
		return MatchRecord{}, false
	}
	return finalizeMatchRecord(MatchRecord{
		ID:            matchRecordID(row["id"]),
		EventName:     normalizeNullableString(row["event_name"]),
		EventDate:     normalizeNullableString(row["event_date"]),
		Player1Pseudo: normalizeNullableString(row["player1_pseudo"]),
		Player2Pseudo: normalizeNullableString(row["player2_pseudo"]),
		Player1Avatar: normalizeNullableString(row["player1_avatar"]),
		Player2Avatar: normalizeNullableString(row["player2_avatar"]),
		Result:        meta.Result,
		Player1Char:   meta.Player1Char,
		Player2Char:   meta.Player2Char,
		Division:      normalizeNullableString(row["division"]),
		Notes:         meta.Notes,
	}), true
}

func queryCompletedFightRowsFromUpcoming(column, pseudo string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows []map[string]interface{}
	_, err := supabaseClient.From("upcoming_fights").
		Select("id,event_name,event_date,player1_pseudo,player2_pseudo,player1_avatar,player2_avatar,division,notes", "", false).
		Filter(column, "ilike", pseudo).
		Order("event_date", &postgrest.OrderOpts{Ascending: false}).
		Limit(limit, "").
		ExecuteTo(&rows)
	return rows, err
}

func queryCompletedFightsFromUpcoming(pseudo string, limit int) ([]MatchRecord, error) {
	rows, err := queryCompletedFightRowsFromUpcoming("player1_pseudo", pseudo, limit)
	if err != nil {
		return nil, err
	}
	rows2, err := queryCompletedFightRowsFromUpcoming("player2_pseudo", pseudo, limit)
	if err != nil {
		return nil, err
	}
	rows = append(rows, rows2...)
	seen := map[string]bool{}
	out := make([]MatchRecord, 0, len(rows))
	for _, row := range rows {
		rec, ok := matchRecordFromUpcomingFightRow(row)
		if !ok {
			continue
		}
		if seen[rec.ID] {
			continue
		}
		seen[rec.ID] = true
		out = append(out, rec)
	}
	sortMatchRecordsDesc(out)
	return out, nil
}

func queryRecentCompletedFightsFromUpcoming(limit int) ([]MatchRecord, error) {
	if limit <= 0 {
		limit = 20
	}
	queryLimit := limit * 4
	if queryLimit < 40 {
		queryLimit = 40
	}
	var rows []map[string]interface{}
	_, err := supabaseClient.From("upcoming_fights").
		Select("id,event_name,event_date,player1_pseudo,player2_pseudo,player1_avatar,player2_avatar,division,notes", "", false).
		Order("event_date", &postgrest.OrderOpts{Ascending: false}).
		Limit(queryLimit, "").
		ExecuteTo(&rows)
	if err != nil {
		return nil, err
	}
	out := make([]MatchRecord, 0, limit)
	for _, row := range rows {
		rec, ok := matchRecordFromUpcomingFightRow(row)
		if !ok {
			continue
		}
		out = append(out, rec)
		if len(out) >= limit {
			break
		}
	}
	sortMatchRecordsDesc(out)
	return out, nil
}

func countCompletedFightsFromUpcoming(pseudonimo string) (int, error) {
	trimmedPseudo := strings.TrimSpace(pseudonimo)
	var rows []map[string]interface{}
	var rows2 []map[string]interface{}

	if _, err := supabaseClient.From("upcoming_fights").
		Select("id,notes", "", false).
		Filter("player1_pseudo", "ilike", trimmedPseudo).
		Limit(250, "").
		ExecuteTo(&rows); err != nil {
		return 0, err
	}
	if _, err := supabaseClient.From("upcoming_fights").
		Select("id,notes", "", false).
		Filter("player2_pseudo", "ilike", trimmedPseudo).
		Limit(250, "").
		ExecuteTo(&rows2); err != nil {
		return 0, err
	}

	seen := map[string]struct{}{}
	for _, row := range append(rows, rows2...) {
		if !isCompletedFightRow(row["notes"]) {
			continue
		}
		id := normalizeNullableString(row["id"])
		if id == "" {
			id = fmt.Sprintf("%v", row["id"])
		}
		if id == "" {
			continue
		}
		seen[id] = struct{}{}
	}
	return len(seen), nil
}

func filterScheduledUpcomingFightRows(rows []map[string]interface{}) []map[string]interface{} {
	filtered := make([]map[string]interface{}, 0, len(rows))
	for _, row := range rows {
		if isCompletedFightRow(row["notes"]) {
			continue
		}
		filtered = append(filtered, row)
	}
	return filtered
}

func insertCompletedFightIntoUpcoming(entry map[string]interface{}) error {
	payload := map[string]interface{}{
		"player1_pseudo": normalizeNullableString(entry["player1_pseudo"]),
		"player2_pseudo": normalizeNullableString(entry["player2_pseudo"]),
		"player1_avatar": normalizeNullableString(entry["player1_avatar"]),
		"player2_avatar": normalizeNullableString(entry["player2_avatar"]),
		"event_date":     normalizeNullableString(entry["event_date"]),
		"event_name":     normalizeNullableString(entry["event_name"]),
		"division":       normalizeNullableString(entry["division"]),
		"notes": encodeCompletedFightNotes(
			normalizeNullableString(entry["result"]),
			normalizeNullableString(entry["player1_char"]),
			normalizeNullableString(entry["player2_char"]),
			normalizeNullableString(entry["notes"]),
		),
	}
	_, err := supabaseClient.From("upcoming_fights").Insert(payload, false, "", "", "").ExecuteTo(nil)
	return err
}

func persistCombatHistory(entry map[string]interface{}) (bool, error) {
	err := insertMatchHistoryCompat(entry)
	if err == nil {
		return false, nil
	}
	log.Printf("⚠️ Error insertando match_history: %v", err)
	if !isSupabaseMissingTableError(err, "match_history") {
		return false, err
	}
	fallbackErr := insertCompletedFightIntoUpcoming(entry)
	if fallbackErr == nil {
		log.Printf("✅ registrarCombate: historial detallado persistido en upcoming_fights fallback")
		return false, nil
	}
	log.Printf("⚠️ Error insertando detalle de combate en upcoming_fights: %v", fallbackErr)
	if isSupabaseMissingTableError(fallbackErr, "upcoming_fights") {
		return true, nil
	}
	return true, fallbackErr
}

func combatesHandler(w http.ResponseWriter, r *http.Request) {
	pseudo := strings.TrimSpace(r.URL.Query().Get("pseudo"))
	if pseudo == "" {
		http.Error(w, `{"error":"pseudo requerido"}`, http.StatusBadRequest)
		return
	}
	var rows []map[string]interface{}
	// Buscamos partidas donde aparece como player1 o player2
	// Supabase postgrest-go no soporta OR directamente; hacemos dos queries y mergeamos
	var rows2 []map[string]interface{}
	if err := runMatchHistorySelectWithFallback(matchHistoryProfileSelectFallbacks(), func(selectExpr string) error {
		rows = nil
		_, err := supabaseClient.From("match_history").
			Select(selectExpr, "", false).
			Filter("player1_pseudo", "ilike", pseudo).
			Order("event_date", &postgrest.OrderOpts{Ascending: false}).
			Limit(50, "").
			ExecuteTo(&rows)
		return err
	}); err != nil {
		log.Printf("ℹ️ combatesHandler player1 query fallback exhausted: %v", err)
	}
	if err := runMatchHistorySelectWithFallback(matchHistoryProfileSelectFallbacks(), func(selectExpr string) error {
		rows2 = nil
		_, err := supabaseClient.From("match_history").
			Select(selectExpr, "", false).
			Filter("player2_pseudo", "ilike", pseudo).
			Order("event_date", &postgrest.OrderOpts{Ascending: false}).
			Limit(50, "").
			ExecuteTo(&rows2)
		return err
	}); err != nil {
		log.Printf("ℹ️ combatesHandler player2 query fallback exhausted: %v", err)
	}
	rows = append(rows, rows2...)

	// Deduplicar por id
	seen := map[string]bool{}
	out := []MatchRecord{}
	for _, row := range rows {
		rec := matchRecordFromHistoryRow(row)
		id := rec.ID
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, rec)
	}
	if len(out) == 0 {
		upcomingOut, upcomingErr := queryCompletedFightsFromUpcoming(pseudo, 50)
		if upcomingErr != nil {
			log.Printf("ℹ️ combatesHandler fallback upcoming_fights failed: %v", upcomingErr)
		} else {
			out = upcomingOut
		}
	}
	sortMatchRecordsDesc(out)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func isSupabaseMissingTableError(err error, table string) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	target := strings.ToLower(strings.TrimSpace(table))
	if target == "" {
		return false
	}
	return strings.Contains(message, "pgrst205") ||
		(strings.Contains(message, "could not find the table") && strings.Contains(message, target)) ||
		(strings.Contains(message, "relation") && strings.Contains(message, target) && strings.Contains(message, "does not exist")) ||
		(strings.Contains(message, "schema cache") && strings.Contains(message, "table") && strings.Contains(message, target))
}

func isSupabaseMissingColumnError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	return strings.Contains(message, "column") &&
		(strings.Contains(message, "does not exist") || strings.Contains(message, "could not find") || strings.Contains(message, "schema cache"))
}

func cloneMap(source map[string]interface{}) map[string]interface{} {
	if len(source) == 0 {
		return map[string]interface{}{}
	}
	clone := make(map[string]interface{}, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func dropMatchHistoryInsertFields(payload map[string]interface{}, fields ...string) map[string]interface{} {
	next := cloneMap(payload)
	changed := false
	for _, field := range fields {
		if _, exists := next[field]; exists {
			delete(next, field)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return next
}

func nextMatchHistoryInsertPayload(payload map[string]interface{}, err error) map[string]interface{} {
	if !isSupabaseMissingColumnError(err) || len(payload) == 0 {
		return nil
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	optionalGroups := [][]string{
		{"player1_char", "player2_char"},
		{"player1_avatar", "player2_avatar"},
		{"division"},
		{"notes"},
	}
	for _, group := range optionalGroups {
		for _, field := range group {
			if strings.Contains(message, field) {
				return dropMatchHistoryInsertFields(payload, group...)
			}
		}
	}
	return dropMatchHistoryInsertFields(payload,
		"player1_char", "player2_char",
		"player1_avatar", "player2_avatar",
		"division", "notes",
	)
}

func insertMatchHistoryCompat(entry map[string]interface{}) error {
	payload := cloneMap(entry)
	for {
		_, err := supabaseClient.From("match_history").Insert(payload, false, "", "", "").ExecuteTo(nil)
		if err == nil {
			return nil
		}
		if isSupabaseMissingTableError(err, "match_history") {
			return err
		}
		nextPayload := nextMatchHistoryInsertPayload(payload, err)
		if nextPayload == nil {
			return err
		}
		payload = nextPayload
	}
}

func runMatchHistorySelectWithFallback(selects []string, query func(selectExpr string) error) error {
	var lastErr error
	for _, selectExpr := range selects {
		err := query(selectExpr)
		if err == nil {
			return nil
		}
		if !isSupabaseMissingColumnError(err) {
			return err
		}
		lastErr = err
	}
	return lastErr
}

func matchHistoryProfileSelectFallbacks() []string {
	return []string{
		"id,event_name,event_date,player1_pseudo,player2_pseudo,player1_avatar,player2_avatar,result,player1_char,player2_char,division,notes",
		"id,event_name,event_date,player1_pseudo,player2_pseudo,result,division,notes",
		"id,event_name,event_date,player1_pseudo,player2_pseudo,result",
	}
}

func matchHistoryRecentSelectFallbacks() []string {
	return []string{
		"id,event_date,event_name,player1_pseudo,player2_pseudo,result,division,notes",
		"id,event_date,event_name,player1_pseudo,player2_pseudo,result",
		"id,event_date,player1_pseudo,player2_pseudo,result",
		"id,player1_pseudo,player2_pseudo,result",
	}
}

type PlayerSnapshot struct {
	Pseudonimo string
	AvatarURL  string
	Wins       int
	Losses     int
	Draws      int
	Streak     int
	RankingPts int
}

type playerSnapshotIndex struct {
	byPseudo map[string]PlayerSnapshot
	byAvatar map[string]PlayerSnapshot
}

func normalizeIdentityKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeAvatarIdentity(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "<nil>" {
		return ""
	}
	return trimmed
}

func playerSnapshotFromRow(row map[string]interface{}) PlayerSnapshot {
	snap := PlayerSnapshot{
		Pseudonimo: normalizeNullableString(row["pseudonimo"]),
		AvatarURL:  normalizeAvatarIdentity(normalizeNullableString(row["avatar_url"])),
	}
	if v, ok := row["wins"].(float64); ok {
		snap.Wins = int(v)
	}
	if v, ok := row["losses"].(float64); ok {
		snap.Losses = int(v)
	}
	if v, ok := row["draws"].(float64); ok {
		snap.Draws = int(v)
	}
	if v, ok := row["current_streak"].(float64); ok {
		snap.Streak = int(v)
	}
	if v, ok := row["ranking_points"].(float64); ok {
		snap.RankingPts = int(v)
	}
	return snap
}

func loadPlayerSnapshotIndex() (playerSnapshotIndex, error) {
	index := playerSnapshotIndex{
		byPseudo: map[string]PlayerSnapshot{},
		byAvatar: map[string]PlayerSnapshot{},
	}
	var roster []map[string]interface{}
	_, err := supabaseClient.From("v_current_roster").
		Select("pseudonimo,avatar_url,wins,losses,draws,current_streak,ranking_points", "", false).
		ExecuteTo(&roster)
	if err != nil {
		return index, err
	}
	for _, row := range roster {
		snap := playerSnapshotFromRow(row)
		if key := normalizeIdentityKey(snap.Pseudonimo); key != "" {
			index.byPseudo[key] = snap
		}
		if avatarKey := normalizeAvatarIdentity(snap.AvatarURL); avatarKey != "" {
			index.byAvatar[avatarKey] = snap
		}
	}
	return index, nil
}

func (index playerSnapshotIndex) Resolve(pseudo, avatarURL string) (PlayerSnapshot, bool) {
	if snap, ok := index.byPseudo[normalizeIdentityKey(pseudo)]; ok {
		return snap, true
	}
	if snap, ok := index.byAvatar[normalizeAvatarIdentity(avatarURL)]; ok {
		return snap, true
	}
	return PlayerSnapshot{}, false
}

func latestAuditRowByFilter(column, operator, value string) (map[string]interface{}, bool, error) {
	if strings.TrimSpace(value) == "" {
		return nil, false, nil
	}
	var rows []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").
		Select("id,pseudonimo,avatar_url", "", false).
		Filter(column, operator, value).
		Order("timestamp", &postgrest.OrderOpts{Ascending: false}).
		Order("id", &postgrest.OrderOpts{Ascending: false}).
		Limit(1, "").
		ExecuteTo(&rows)
	if err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return rows[0], true, nil
}

func loadCompetitiveProfileRow(profileID string) (map[string]interface{}, bool, error) {
	trimmedProfileID := strings.TrimSpace(profileID)
	if trimmedProfileID == "" {
		return nil, false, nil
	}
	var rows []map[string]interface{}
	_, err := supabaseClient.From("player_competitive_profiles").
		Select("id,source_audit_log_id,hardware_fingerprint,top_char_1,top_char_2,top_char_3", "", false).
		Filter("id", "eq", trimmedProfileID).
		Limit(1, "").
		ExecuteTo(&rows)
	if err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	return rows[0], true, nil
}

func findCompetitiveProfileForIdentity(auditID, pseudo, hardwareFingerprint string) (map[string]interface{}, bool, error) {
	trimmedAuditID := strings.TrimSpace(auditID)
	if trimmedAuditID != "" {
		var rows []map[string]interface{}
		_, err := supabaseClient.From("player_competitive_profiles").
			Select("id,source_audit_log_id,hardware_fingerprint,top_char_1,top_char_2,top_char_3", "", false).
			Filter("source_audit_log_id", "eq", trimmedAuditID).
			Limit(1, "").
			ExecuteTo(&rows)
		if err != nil {
			return nil, false, err
		}
		if len(rows) > 0 {
			return rows[0], true, nil
		}
	}

	trimmedPseudo := strings.TrimSpace(pseudo)
	if trimmedPseudo != "" {
		var rosterRows []map[string]interface{}
		_, err := supabaseClient.From("v_current_roster").
			Select("player_profile_id", "", false).
			Filter("pseudonimo", "ilike", trimmedPseudo).
			Limit(1, "").
			ExecuteTo(&rosterRows)
		if err != nil {
			return nil, false, err
		}
		if len(rosterRows) > 0 {
			if profileID := normalizeNullableString(rosterRows[0]["player_profile_id"]); profileID != "" {
				return loadCompetitiveProfileRow(profileID)
			}
		}
	}

	trimmedFingerprint := strings.TrimSpace(hardwareFingerprint)
	if trimmedFingerprint != "" {
		var rows []map[string]interface{}
		_, err := supabaseClient.From("player_competitive_profiles").
			Select("id,source_audit_log_id,hardware_fingerprint,top_char_1,top_char_2,top_char_3", "", false).
			Filter("hardware_fingerprint", "eq", trimmedFingerprint).
			Order("id", &postgrest.OrderOpts{Ascending: false}).
			Limit(1, "").
			ExecuteTo(&rows)
		if err != nil {
			return nil, false, err
		}
		if len(rows) > 0 {
			return rows[0], true, nil
		}
	}

	return nil, false, nil
}

func syncCompetitiveProfileAuditLink(auditID, pseudo, hardwareFingerprint string) (map[string]interface{}, error) {
	trimmedAuditID := strings.TrimSpace(auditID)
	if trimmedAuditID == "" {
		return nil, nil
	}
	profileRow, ok, err := findCompetitiveProfileForIdentity(trimmedAuditID, pseudo, hardwareFingerprint)
	if err != nil || !ok {
		return profileRow, err
	}
	profileID := normalizeNullableString(profileRow["id"])
	if profileID == "" {
		return profileRow, nil
	}

	updates := map[string]interface{}{}
	if normalizeNullableString(profileRow["source_audit_log_id"]) != trimmedAuditID {
		updates["source_audit_log_id"] = trimmedAuditID
	}
	trimmedFingerprint := strings.TrimSpace(hardwareFingerprint)
	if trimmedFingerprint != "" && normalizeNullableString(profileRow["hardware_fingerprint"]) != trimmedFingerprint {
		updates["hardware_fingerprint"] = trimmedFingerprint
	}
	if len(updates) == 0 {
		return profileRow, nil
	}

	_, _, err = supabaseClient.From("player_competitive_profiles").
		Update(updates, "", "").
		Filter("id", "eq", profileID).
		Execute()
	if err != nil {
		return profileRow, err
	}
	for key, value := range updates {
		profileRow[key] = value
	}
	return profileRow, nil
}

func findLatestAuditIdentityRow(pseudo, avatarURL string) (map[string]interface{}, error) {
	if row, ok, err := latestAuditRowByFilter("pseudonimo", "ilike", strings.TrimSpace(pseudo)); err != nil {
		return nil, err
	} else if ok {
		return row, nil
	}
	if row, ok, err := latestAuditRowByFilter("avatar_url", "eq", normalizeAvatarIdentity(avatarURL)); err != nil {
		return nil, err
	} else if ok {
		return row, nil
	}
	return nil, fmt.Errorf("jugador no encontrado: %s", strings.TrimSpace(pseudo))
}

func updatePlayerStatsByIdentity(pseudo, avatarURL string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}
	auditRow, err := findLatestAuditIdentityRow(pseudo, avatarURL)
	if err != nil {
		return err
	}
	auditID := fmt.Sprintf("%v", auditRow["id"])
	_, _, updErr := supabaseClient.From("player_competitive_profiles").
		Update(updates, "", "").
		Filter("source_audit_log_id", "eq", auditID).
		Execute()
	return updErr
}

func applyRankingPointsOperation(current int, operation string, amount int) (int, int, error) {
	switch strings.ToLower(strings.TrimSpace(operation)) {
	case "", "add", "sumar":
		if amount <= 0 {
			return current, 0, fmt.Errorf("cantidad_invalida")
		}
		return current + amount, amount, nil
	case "subtract", "sub", "restar":
		if amount <= 0 {
			return current, 0, fmt.Errorf("cantidad_invalida")
		}
		next := current - amount
		if next < 0 {
			next = 0
		}
		return next, next - current, nil
	case "set", "fijar":
		if amount < 0 {
			return current, 0, fmt.Errorf("cantidad_invalida")
		}
		return amount, amount - current, nil
	default:
		return current, 0, fmt.Errorf("operacion_invalida")
	}
}

func decrementPositiveStreak(value int) int {
	if value > 0 {
		return value - 1
	}
	return value
}

func incrementNegativeStreak(value int) int {
	if value < 0 {
		return value + 1
	}
	return value
}

func buildReverseFightStatUpdates(result string, snap1, snap2 PlayerSnapshot) (map[string]interface{}, map[string]interface{}) {
	new1 := map[string]interface{}{}
	new2 := map[string]interface{}{}
	switch result {
	case "player1":
		new1["wins"] = maxInt(0, snap1.Wins-1)
		new1["current_streak"] = decrementPositiveStreak(snap1.Streak)
		new2["losses"] = maxInt(0, snap2.Losses-1)
		new2["current_streak"] = incrementNegativeStreak(snap2.Streak)
	case "player2":
		new1["losses"] = maxInt(0, snap1.Losses-1)
		new1["current_streak"] = incrementNegativeStreak(snap1.Streak)
		new2["wins"] = maxInt(0, snap2.Wins-1)
		new2["current_streak"] = decrementPositiveStreak(snap2.Streak)
	default:
		new1["draws"] = maxInt(0, snap1.Draws-1)
		new1["current_streak"] = 0
		new2["draws"] = maxInt(0, snap2.Draws-1)
		new2["current_streak"] = 0
	}
	return new1, new2
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func loadCombatRecordForDelete(id string) (MatchRecord, string, error) {
	var rows []map[string]interface{}
	matchErr := runMatchHistorySelectWithFallback(matchHistoryProfileSelectFallbacks(), func(selectExpr string) error {
		rows = nil
		_, err := supabaseClient.From("match_history").
			Select(selectExpr, "", false).
			Filter("id", "eq", id).
			Limit(1, "").
			ExecuteTo(&rows)
		return err
	})
	if matchErr == nil && len(rows) > 0 {
		return matchRecordFromHistoryRow(rows[0]), "match_history", nil
	}

	var upcomingRows []map[string]interface{}
	_, upcomingErr := supabaseClient.From("upcoming_fights").
		Select("id,event_name,event_date,player1_pseudo,player2_pseudo,player1_avatar,player2_avatar,division,notes", "", false).
		Filter("id", "eq", id).
		Limit(1, "").
		ExecuteTo(&upcomingRows)
	if upcomingErr == nil && len(upcomingRows) > 0 {
		record, ok := matchRecordFromUpcomingFightRow(upcomingRows[0])
		if ok {
			return record, "upcoming_fights", nil
		}
	}
	if upcomingErr != nil {
		return MatchRecord{}, "", upcomingErr
	}
	if matchErr != nil {
		return MatchRecord{}, "", matchErr
	}
	return MatchRecord{}, "", fmt.Errorf("combate no encontrado: %s", id)
}

// ── POST /api/admin/combate ─────────────────────────────────────────────────
// Registra un combate real y actualiza wins/losses/draws/streak de ambos jugadores.
func registrarCombateHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EventName     string `json:"event_name"`
		EventDate     string `json:"event_date"`
		Player1Pseudo string `json:"player1_pseudo"`
		Player2Pseudo string `json:"player2_pseudo"`
		Result        string `json:"result"` // "player1" | "player2" | "draw"
		Player1Char   string `json:"player1_char"`
		Player2Char   string `json:"player2_char"`
		Division      string `json:"division"`
		Notes         string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"body inválido"}`, http.StatusBadRequest)
		return
	}
	req.Player1Pseudo = strings.TrimSpace(req.Player1Pseudo)
	req.Player2Pseudo = strings.TrimSpace(req.Player2Pseudo)
	if req.Player1Pseudo == "" || req.Player2Pseudo == "" {
		http.Error(w, `{"error":"ambos pseudónimos requeridos"}`, http.StatusBadRequest)
		return
	}
	if strings.EqualFold(req.Player1Pseudo, req.Player2Pseudo) {
		http.Error(w, `{"error":"no pueden ser el mismo jugador"}`, http.StatusBadRequest)
		return
	}
	if req.Result != "player1" && req.Result != "player2" && req.Result != "draw" {
		http.Error(w, `{"error":"result debe ser player1, player2 o draw"}`, http.StatusBadRequest)
		return
	}
	if req.EventDate == "" {
		req.EventDate = time.Now().Format("2006-01-02")
	}
	if req.EventName == "" {
		req.EventName = "Torneo Bellator 2026"
	}

	// ── 1. Obtener datos actuales de ambos jugadores desde la vista ─────────
	snapshotIndex, snapshotErr := loadPlayerSnapshotIndex()
	if snapshotErr != nil {
		log.Printf("⚠️ No se pudo cargar el roster para registrar combate: %v", snapshotErr)
	}
	snap1, _ := snapshotIndex.Resolve(req.Player1Pseudo, "")
	snap2, _ := snapshotIndex.Resolve(req.Player2Pseudo, "")

	// ── 2. Calcular nuevos stats ────────────────────────────────────────────
	var new1, new2 map[string]interface{}
	switch req.Result {
	case "player1": // player1 gana
		newStreak1 := snap1.Streak
		if newStreak1 < 0 {
			newStreak1 = 0
		}
		newStreak1++
		newStreak2 := snap2.Streak
		if newStreak2 > 0 {
			newStreak2 = 0
		}
		newStreak2--
		new1 = map[string]interface{}{"wins": snap1.Wins + 1, "current_streak": newStreak1}
		new2 = map[string]interface{}{"losses": snap2.Losses + 1, "current_streak": newStreak2}
	case "player2": // player2 gana
		newStreak2 := snap2.Streak
		if newStreak2 < 0 {
			newStreak2 = 0
		}
		newStreak2++
		newStreak1 := snap1.Streak
		if newStreak1 > 0 {
			newStreak1 = 0
		}
		newStreak1--
		new1 = map[string]interface{}{"losses": snap1.Losses + 1, "current_streak": newStreak1}
		new2 = map[string]interface{}{"wins": snap2.Wins + 1, "current_streak": newStreak2}
	case "draw":
		new1 = map[string]interface{}{"draws": snap1.Draws + 1, "current_streak": 0}
		new2 = map[string]interface{}{"draws": snap2.Draws + 1, "current_streak": 0}
	}

	// ── 3. Insertar en match_history antes de tocar stats agregadas ─────────
	av1 := snap1.AvatarURL
	if av1 == "<nil>" {
		av1 = ""
	}
	av2 := snap2.AvatarURL
	if av2 == "<nil>" {
		av2 = ""
	}

	entry := map[string]interface{}{
		"event_name":     req.EventName,
		"event_date":     req.EventDate,
		"player1_pseudo": req.Player1Pseudo,
		"player2_pseudo": req.Player2Pseudo,
		"player1_avatar": av1,
		"player2_avatar": av2,
		"result":         req.Result,
		"player1_char":   req.Player1Char,
		"player2_char":   req.Player2Char,
		"division":       req.Division,
		"notes":          req.Notes,
	}
	historyWarn, err := persistCombatHistory(entry)
	if err != nil {
		http.Error(w, `{"error":"error al guardar historial"}`, http.StatusInternalServerError)
		return
	}

	// ── 4. Actualizar player_competitive_profiles para ambos jugadores ──────
	errStats1 := updatePlayerStatsByIdentity(req.Player1Pseudo, av1, new1)
	errStats2 := updatePlayerStatsByIdentity(req.Player2Pseudo, av2, new2)
	if errStats1 != nil {
		log.Printf("⚠️ Stats %s: %v", req.Player1Pseudo, errStats1)
	}
	if errStats2 != nil {
		log.Printf("⚠️ Stats %s: %v", req.Player2Pseudo, errStats2)
	}

	winnerLabel := req.Player1Pseudo
	if req.Result == "player2" {
		winnerLabel = req.Player2Pseudo
	}
	if req.Result == "draw" {
		winnerLabel = "EMPATE"
	}
	log.Printf("⚔️  Combate: %s vs %s → %s | Stats actualizados: P1_err=%v P2_err=%v",
		req.Player1Pseudo, req.Player2Pseudo, winnerLabel, errStats1, errStats2)

	// Resolver apuestas de upcoming_fights y limpiar
	go func() {
		resolveBetsForMatch(req.Player1Pseudo, req.Player2Pseudo, winnerLabel)
		supabaseClient.From("upcoming_fights").Delete("", "").Filter("notes", "not.like", "__bellator_completed__*").Eq("player1_pseudo", req.Player1Pseudo).Eq("player2_pseudo", req.Player2Pseudo).Execute()
		supabaseClient.From("upcoming_fights").Delete("", "").Filter("notes", "not.like", "__bellator_completed__*").Eq("player1_pseudo", req.Player2Pseudo).Eq("player2_pseudo", req.Player1Pseudo).Execute()
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"winner":       winnerLabel,
		"p1_warn":      errStats1 != nil,
		"p2_warn":      errStats2 != nil,
		"history_warn": historyWarn,
	})
}

// ── DELETE /api/admin/combate/{id} ─────────────────────────────────────────
func eliminarCombateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, `{"error":"id requerido"}`, http.StatusBadRequest)
		return
	}
	record, sourceTable, err := loadCombatRecordForDelete(id)
	if err != nil {
		http.Error(w, `{"error":"combate no encontrado"}`, http.StatusNotFound)
		return
	}

	switch sourceTable {
	case "match_history":
		_, err = supabaseClient.From("match_history").Delete("", "").Filter("id", "eq", id).ExecuteTo(nil)
	case "upcoming_fights":
		_, err = supabaseClient.From("upcoming_fights").Delete("", "").Filter("id", "eq", id).ExecuteTo(nil)
	default:
		err = fmt.Errorf("tabla de combate desconocida")
	}
	if err != nil {
		http.Error(w, `{"error":"error al eliminar"}`, http.StatusInternalServerError)
		return
	}

	snapshotIndex, snapshotErr := loadPlayerSnapshotIndex()
	if snapshotErr != nil {
		log.Printf("⚠️ No se pudo cargar roster al eliminar combate %s: %v", id, snapshotErr)
	}
	snap1, _ := snapshotIndex.Resolve(record.Player1Pseudo, record.Player1Avatar)
	snap2, _ := snapshotIndex.Resolve(record.Player2Pseudo, record.Player2Avatar)
	reverse1, reverse2 := buildReverseFightStatUpdates(record.Result, snap1, snap2)
	errStats1 := updatePlayerStatsByIdentity(firstNonEmpty(snap1.Pseudonimo, record.Player1Pseudo), record.Player1Avatar, reverse1)
	errStats2 := updatePlayerStatsByIdentity(firstNonEmpty(snap2.Pseudonimo, record.Player2Pseudo), record.Player2Avatar, reverse2)
	if errStats1 != nil {
		log.Printf("⚠️ Revirtiendo stats %s: %v", record.Player1Pseudo, errStats1)
	}
	if errStats2 != nil {
		log.Printf("⚠️ Revirtiendo stats %s: %v", record.Player2Pseudo, errStats2)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "deleted", "p1_warn": errStats1 != nil, "p2_warn": errStats2 != nil})
}

// ── GET /api/admin/combates-recientes ──────────────────────────────────────
// Devuelve los últimos 20 combates registrados (solo admin).
func combatesRecientesHandler(w http.ResponseWriter, r *http.Request) {
	var results []map[string]interface{}
	err := runMatchHistorySelectWithFallback(matchHistoryRecentSelectFallbacks(), func(selectExpr string) error {
		results = nil
		_, err := supabaseClient.From("match_history").
			Select(selectExpr, "", false).
			Order("event_date", &postgrest.OrderOpts{Ascending: false}).
			Limit(20, "").
			ExecuteTo(&results)
		return err
	})
	if err != nil || len(results) == 0 {
		upcomingOut, upcomingErr := queryRecentCompletedFightsFromUpcoming(20)
		if upcomingErr == nil && len(upcomingOut) > 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(upcomingOut)
			return
		}
		// match_history puede no existir aún — devolver lista vacía en lugar de 500
		log.Printf("ℹ️ combates-recientes (tabla puede no existir): %v", err)
		results = []map[string]interface{}{}
	}
	if results == nil {
		results = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// ── GET /api/proximas-peleas ────────────────────────────────────────────────
func proximasPeleasHandler(w http.ResponseWriter, r *http.Request) {
	var results []map[string]interface{}
	_, err := supabaseClient.From("upcoming_fights").
		Select("*", "", false).
		Order("event_date", &postgrest.OrderOpts{Ascending: true}).
		ExecuteTo(&results)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	results = filterScheduledUpcomingFightRows(results)
	if results == nil {
		results = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// ── POST /api/admin/proxima-pelea ───────────────────────────────────────────
func crearProximaPeleaHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Player1Pseudo string `json:"player1_pseudo"`
		Player2Pseudo string `json:"player2_pseudo"`
		EventDate     string `json:"event_date"`
		EventName     string `json:"event_name"`
		Division      string `json:"division"`
		Notes         string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"body inválido"}`, http.StatusBadRequest)
		return
	}
	req.Player1Pseudo = strings.TrimSpace(req.Player1Pseudo)
	req.Player2Pseudo = strings.TrimSpace(req.Player2Pseudo)
	if req.Player1Pseudo == "" || req.Player2Pseudo == "" || req.EventDate == "" {
		http.Error(w, `{"error":"player1, player2 y fecha requeridos"}`, http.StatusBadRequest)
		return
	}
	if req.EventName == "" {
		req.EventName = "Bellator RolBattle"
	}
	// Auto-fetch avatares
	var rosterAv []map[string]interface{}
	supabaseClient.From("v_current_roster").Select("pseudonimo,avatar_url", "", false).ExecuteTo(&rosterAv)
	av := map[string]string{}
	for _, p := range rosterAv {
		ps := strings.ToLower(fmt.Sprintf("%v", p["pseudonimo"]))
		url := fmt.Sprintf("%v", p["avatar_url"])
		if url != "<nil>" && url != "" {
			av[ps] = url
		}
	}
	entry := map[string]interface{}{
		"player1_pseudo": req.Player1Pseudo,
		"player2_pseudo": req.Player2Pseudo,
		"player1_avatar": av[strings.ToLower(req.Player1Pseudo)],
		"player2_avatar": av[strings.ToLower(req.Player2Pseudo)],
		"event_date":     req.EventDate,
		"event_name":     req.EventName,
		"division":       req.Division,
		"notes":          req.Notes,
	}
	var res []map[string]interface{}
	_, err := supabaseClient.From("upcoming_fights").Insert(entry, false, "", "", "").ExecuteTo(&res)
	if err != nil {
		log.Printf("⚠️ Error creando próxima pelea: %v", err)
		http.Error(w, `{"error":"error al guardar"}`, http.StatusInternalServerError)
		return
	}
	log.Printf("📅 Próxima pelea: %s vs %s el %s", req.Player1Pseudo, req.Player2Pseudo, req.EventDate)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ── DELETE /api/admin/proxima-pelea/{id} ────────────────────────────────────
func eliminarProximaPeleaHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, `{"error":"id requerido"}`, http.StatusBadRequest)
		return
	}
	_, err := supabaseClient.From("upcoming_fights").Delete("", "").Filter("id", "eq", id).ExecuteTo(nil)
	if err != nil {
		http.Error(w, `{"error":"error al eliminar"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// ── DELETE /api/admin/jugador/{pseudonimo} ───────────────────────────────
// Elimina un jugador del sistema (perfil, combates, próximas peleas, clanes).
func eliminarJugadorHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	pseudo := strings.TrimSpace(vars["pseudonimo"])
	if pseudo == "" {
		http.Error(w, `{"error":"pseudonimo requerido"}`, http.StatusBadRequest)
		return
	}

	warnings := []string{}

	var auditRows []map[string]interface{}
	_, auditErr := supabaseClient.From("audit_logs").
		Select("id", "", false).
		Filter("pseudonimo", "ilike", pseudo).
		ExecuteTo(&auditRows)
	if auditErr != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}

	for _, row := range auditRows {
		auditID := fmt.Sprintf("%v", row["id"])
		if auditID == "" {
			continue
		}
		_, _, profErr := supabaseClient.From("player_competitive_profiles").
			Delete("", "").
			Filter("source_audit_log_id", "eq", auditID).
			Execute()
		if profErr != nil {
			warnings = append(warnings, "profile_delete_failed")
			log.Printf("⚠️ delete player: profile delete failed for %s (%v)", auditID, profErr)
		}
	}

	_, err := supabaseClient.From("match_history").
		Delete("", "").
		Filter("player1_pseudo", "ilike", pseudo).
		ExecuteTo(nil)
	if err != nil {
		warnings = append(warnings, "match_history_p1_delete_failed")
		log.Printf("⚠️ delete player: match_history p1 delete failed for %s (%v)", pseudo, err)
	}

	_, err = supabaseClient.From("match_history").
		Delete("", "").
		Filter("player2_pseudo", "ilike", pseudo).
		ExecuteTo(nil)
	if err != nil {
		warnings = append(warnings, "match_history_p2_delete_failed")
		log.Printf("⚠️ delete player: match_history p2 delete failed for %s (%v)", pseudo, err)
	}

	_, err = supabaseClient.From("upcoming_fights").
		Delete("", "").
		Filter("player1_pseudo", "ilike", pseudo).
		ExecuteTo(nil)
	if err != nil {
		warnings = append(warnings, "upcoming_fights_p1_delete_failed")
		log.Printf("⚠️ delete player: upcoming_fights p1 delete failed for %s (%v)", pseudo, err)
	}

	_, err = supabaseClient.From("upcoming_fights").
		Delete("", "").
		Filter("player2_pseudo", "ilike", pseudo).
		ExecuteTo(nil)
	if err != nil {
		warnings = append(warnings, "upcoming_fights_p2_delete_failed")
		log.Printf("⚠️ delete player: upcoming_fights p2 delete failed for %s (%v)", pseudo, err)
	}

	if clanErr := removePlayerFromClans(pseudo); clanErr != nil {
		warnings = append(warnings, "clan_update_failed")
		log.Printf("⚠️ delete player: clan cleanup failed for %s (%v)", pseudo, clanErr)
	}

	_, err = supabaseClient.From("audit_logs").
		Delete("", "").
		Filter("pseudonimo", "ilike", pseudo).
		ExecuteTo(nil)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{"status": "deleted"}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}
	json.NewEncoder(w).Encode(resp)
}

// ── POST /api/admin/player-keys/reset-all ────────────────────────────────
// Aplica una nueva clave temporal común a todos los pseudónimos registrados.
func resetAllPlayerKeysHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NewKey string `json:"new_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"body_invalido"}`, http.StatusBadRequest)
		return
	}
	newKey := strings.TrimSpace(req.NewKey)
	if newKey == "" {
		http.Error(w, `{"error":"clave_requerida"}`, http.StatusBadRequest)
		return
	}
	if len(newKey) < 6 {
		http.Error(w, `{"error":"clave_muy_corta"}`, http.StatusBadRequest)
		return
	}
	if len(newKey) > 64 {
		http.Error(w, `{"error":"clave_muy_larga"}`, http.StatusBadRequest)
		return
	}

	var auditRows []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").
		Select("pseudonimo", "", false).
		Filter("pseudonimo", "neq", "").
		Limit(5000, "").
		ExecuteTo(&auditRows)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}

	uniquePlayers := make(map[string]struct{})
	for _, row := range auditRows {
		pseudo := strings.TrimSpace(normalizeNullableString(row["pseudonimo"]))
		if pseudo == "" {
			continue
		}
		uniquePlayers[strings.ToLower(pseudo)] = struct{}{}
	}
	if len(uniquePlayers) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":           "ok",
			"players_affected": 0,
		})
		return
	}

	h := sha256.Sum256([]byte(newKey))
	_, _, err = supabaseClient.From("audit_logs").
		Update(map[string]interface{}{"player_key_hash": hex.EncodeToString(h[:])}, "", "").
		Filter("pseudonimo", "neq", "").
		Execute()
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}

	clientIP := requestClientIP(r)
	log.Printf("🔐 ADMIN RESET ALL PLAYER KEYS: players=%d ip=%s", len(uniquePlayers), compactAuditValue(clientIP, 64))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":           "ok",
		"players_affected": len(uniquePlayers),
	})
}

// ── POST /api/admin/player-keys/reset ────────────────────────────────────
// Aplica una nueva clave temporal a un pseudónimo concreto.
func resetSinglePlayerKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pseudonimo string `json:"pseudonimo"`
		NewKey     string `json:"new_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"body_invalido"}`, http.StatusBadRequest)
		return
	}
	pseudonimo := strings.TrimSpace(req.Pseudonimo)
	newKey := strings.TrimSpace(req.NewKey)
	if pseudonimo == "" {
		http.Error(w, `{"error":"pseudonimo_requerido"}`, http.StatusBadRequest)
		return
	}
	if newKey == "" {
		http.Error(w, `{"error":"clave_requerida"}`, http.StatusBadRequest)
		return
	}
	if len(newKey) < 6 {
		http.Error(w, `{"error":"clave_muy_corta"}`, http.StatusBadRequest)
		return
	}
	if len(newKey) > 64 {
		http.Error(w, `{"error":"clave_muy_larga"}`, http.StatusBadRequest)
		return
	}

	var auditRows []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").
		Select("pseudonimo", "", false).
		Filter("pseudonimo", "ilike", pseudonimo).
		Limit(1, "").
		ExecuteTo(&auditRows)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	if len(auditRows) == 0 {
		http.Error(w, `{"error":"jugador_no_encontrado"}`, http.StatusNotFound)
		return
	}
	resolvedPseudo := normalizeNullableString(auditRows[0]["pseudonimo"])
	if resolvedPseudo == "" {
		resolvedPseudo = pseudonimo
	}

	h := sha256.Sum256([]byte(newKey))
	_, _, err = supabaseClient.From("audit_logs").
		Update(map[string]interface{}{"player_key_hash": hex.EncodeToString(h[:])}, "", "").
		Filter("pseudonimo", "ilike", resolvedPseudo).
		Execute()
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}

	clientIP := requestClientIP(r)
	log.Printf("🔐 ADMIN RESET PLAYER KEY: pseudo=%s ip=%s", compactAuditValue(resolvedPseudo, 48), compactAuditValue(clientIP, 64))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"pseudonimo": resolvedPseudo,
	})
}

func removePlayerFromClans(pseudo string) error {
	var clans []map[string]interface{}
	_, err := supabaseClient.From("clans").
		Select("id,members", "", false).
		ExecuteTo(&clans)
	if err != nil {
		return err
	}
	for _, clan := range clans {
		id := fmt.Sprintf("%v", clan["id"])
		if id == "" {
			continue
		}
		members := []string{}
		changed := false
		if m, ok := clan["members"]; ok && m != nil {
			if arr, ok := m.([]interface{}); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok {
						if strings.EqualFold(strings.TrimSpace(s), pseudo) {
							changed = true
							continue
						}
						members = append(members, s)
					}
				}
			}
		}
		if !changed {
			continue
		}
		_, updErr := supabaseClient.From("clans").
			Update(map[string]interface{}{"members": members}, "", "").
			Filter("id", "eq", id).
			ExecuteTo(nil)
		if updErr != nil {
			return updErr
		}
	}
	return nil
}

// ── POST /api/admin/jugador/personajes ──────────────────────────────────────
// Actualiza los 3 personajes más usados de un jugador, con imágenes opcionales.
func actualizarPersonajesHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pseudo     string `json:"pseudo"`
		Char1      string `json:"char1"`
		Char2      string `json:"char2"`
		Char3      string `json:"char3"`
		Char1Image string `json:"char1_image"`
		Char2Image string `json:"char2_image"`
		Char3Image string `json:"char3_image"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Pseudo) == "" {
		http.Error(w, `{"error":"pseudo requerido"}`, http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(req.Char1Image)) > 512 || len(strings.TrimSpace(req.Char2Image)) > 512 || len(strings.TrimSpace(req.Char3Image)) > 512 {
		http.Error(w, `{"error":"char_imagen_muy_larga"}`, http.StatusBadRequest)
		return
	}
	if !isAllowedCharacterImageURL(req.Char1Image) || !isAllowedCharacterImageURL(req.Char2Image) || !isAllowedCharacterImageURL(req.Char3Image) {
		http.Error(w, `{"error":"char_imagen_invalida"}`, http.StatusBadRequest)
		return
	}
	var auditRows []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").
		Select("id", "", false).
		Filter("pseudonimo", "ilike", strings.TrimSpace(req.Pseudo)).
		Limit(1, "").
		ExecuteTo(&auditRows)
	if err != nil || len(auditRows) == 0 {
		http.Error(w, `{"error":"jugador no encontrado"}`, http.StatusNotFound)
		return
	}
	auditID := fmt.Sprintf("%v", auditRows[0]["id"])
	updates := map[string]interface{}{
		"top_char_1": encodeCharacterSlot(req.Char1, req.Char1Image),
		"top_char_2": encodeCharacterSlot(req.Char2, req.Char2Image),
		"top_char_3": encodeCharacterSlot(req.Char3, req.Char3Image),
	}
	_, _, updErr := supabaseClient.From("player_competitive_profiles").
		Update(updates, "", "").
		Filter("source_audit_log_id", "eq", auditID).
		Execute()
	if updErr != nil {
		log.Printf("⚠️ Error actualizando personajes: %v", updErr)
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	log.Printf("🎭 Personajes de %s: %s / %s / %s", req.Pseudo, req.Char1, req.Char2, req.Char3)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ── POST /api/admin/jugador/ranking ────────────────────────────────────────
// Ajusta manualmente los puntos de ranking de un jugador existente.
func actualizarRankingPointsHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Pseudonimo string `json:"pseudonimo"`
		Operation  string `json:"operation"`
		Amount     int    `json:"amount"`
		Reason     string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"body_invalido"}`, http.StatusBadRequest)
		return
	}

	pseudonimo := strings.TrimSpace(req.Pseudonimo)
	reason := strings.TrimSpace(req.Reason)
	if pseudonimo == "" {
		http.Error(w, `{"error":"pseudonimo_requerido"}`, http.StatusBadRequest)
		return
	}
	if len(reason) > 240 {
		http.Error(w, `{"error":"motivo_muy_largo"}`, http.StatusBadRequest)
		return
	}

	index, err := loadPlayerSnapshotIndex()
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	snap, ok := index.Resolve(pseudonimo, "")
	if !ok {
		http.Error(w, `{"error":"jugador_no_encontrado"}`, http.StatusNotFound)
		return
	}

	nextPoints, delta, calcErr := applyRankingPointsOperation(snap.RankingPts, req.Operation, req.Amount)
	if calcErr != nil {
		switch calcErr.Error() {
		case "cantidad_invalida":
			http.Error(w, `{"error":"cantidad_invalida"}`, http.StatusBadRequest)
		default:
			http.Error(w, `{"error":"operacion_invalida"}`, http.StatusBadRequest)
		}
		return
	}

	resolvedPseudo := firstNonEmpty(snap.Pseudonimo, pseudonimo)
	if err := updatePlayerStatsByIdentity(resolvedPseudo, snap.AvatarURL, map[string]interface{}{"ranking_points": nextPoints}); err != nil {
		log.Printf("⚠️ admin ranking update failed for %s: %v", compactAuditValue(resolvedPseudo, 48), err)
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}

	clientIP := requestClientIP(r)
	log.Printf(
		"🏅 ADMIN RANKING UPDATE: pseudo=%s op=%s req=%d delta=%d prev=%d next=%d reason=%s ip=%s",
		compactAuditValue(resolvedPseudo, 48),
		compactAuditValue(strings.TrimSpace(req.Operation), 16),
		req.Amount,
		delta,
		snap.RankingPts,
		nextPoints,
		compactAuditValue(reason, 96),
		compactAuditValue(clientIP, 64),
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":          "ok",
		"pseudonimo":      resolvedPseudo,
		"previous_points": snap.RankingPts,
		"ranking_points":  nextPoints,
		"delta":           delta,
	})
}

func tournamentFightsHandler(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := fmt.Sscanf(l, "%d", &limit); n != 1 || err != nil || limit < 1 || limit > 200 {
			limit = 50
		}
	}
	var results []map[string]interface{}
	q := supabaseClient.From("fights").
		Select("id,division_id,result_type,result_detail,rounds_scheduled,finish_round,finish_time,title_fight,is_main_event,created_at", "", false).
		Order("created_at", &postgrest.OrderOpts{Ascending: false}).
		Limit(limit, "")
	if div := r.URL.Query().Get("division_id"); div != "" {
		q = q.Filter("division_id", "eq", div)
	}
	_, err := q.ExecuteTo(&results)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// ── GET /api/schedule ──────────────────────────────────────────────────────
// Calendario estático de la temporada 2026 Bellator RolBattle.
func publicScheduleHandler(w http.ResponseWriter, r *http.Request) {
	type Round struct {
		Ronda  int    `json:"ronda"`
		Nombre string `json:"nombre"`
		Fecha  string `json:"fecha"`
		Pais   string `json:"pais"`
		Estado string `json:"estado"` // "completado" | "activo" | "pendiente"
	}
	schedule := []Round{
		{1, "Ronda de Clasificación", "2026-01-15", "Colombia", "completado"},
		{2, "Primera Eliminatoria", "2026-02-05", "Colombia", "completado"},
		{3, "Cuartos de Final Universal", "2026-03-12", "Colombia", "activo"},
		{4, "Cuartos de Final Ciudad", "2026-04-03", "Colombia", "pendiente"},
		{5, "Semifinal Universal", "2026-05-14", "Colombia", "pendiente"},
		{6, "Semifinal Ciudad", "2026-06-11", "Colombia", "pendiente"},
		{7, "Gran Final Bellator 2026", "2026-07-19", "Colombia", "pendiente"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schedule)
}

// ── GET /api/docs  ·  GET /api ─────────────────────────────────────────────
// Documentación de todos los endpoints disponibles.
func apiDocsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"nombre":  "Bellator RolBattle API",
		"version": "v1",
		"status":  "operational",
		"endpoints": []map[string]string{
			{"method": "GET", "path": "/api/competidores"},
			{"method": "GET", "path": "/api/stats"},
			{"method": "GET", "path": "/api/schedule"},
			{"method": "GET", "path": "/api/rankings"},
			{"method": "GET", "path": "/api/champions"},
			{"method": "GET", "path": "/api/fights"},
			{"method": "GET", "path": "/api/clanes"},
		},
	})
}

// ── CLANES / LINAJES ────────────────────────────────────────────────────────

// getClanesHandler devuelve todos los clanes incluyendo miembros.
func getClanesHandler(w http.ResponseWriter, r *http.Request) {
	var results []map[string]interface{}
	_, err := supabaseClient.From("clans").
		Select("id,name,description,logo_url,leader_pseudonimo,members,primary_color,created_at", "", false).
		Order("created_at", &postgrest.OrderOpts{Ascending: false}).
		ExecuteTo(&results)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	if results == nil {
		results = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// createClanHandler crea un nuevo clan.
// Body JSON: {name, description, logo_url, leader_pseudonimo, members, primary_color, clan_key}
func createClanHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name             string   `json:"name"`
		Description      string   `json:"description"`
		LogoURL          string   `json:"logo_url"`
		LeaderPseudonimo string   `json:"leader_pseudonimo"`
		Members          []string `json:"members"`
		PrimaryColor     string   `json:"primary_color"`
		ClanKey          string   `json:"clan_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		http.Error(w, `{"error":"nombre_requerido"}`, http.StatusBadRequest)
		return
	}
	if len(body.Name) > 64 {
		http.Error(w, `{"error":"nombre_muy_largo"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(body.ClanKey) == "" {
		http.Error(w, `{"error":"clave_requerida"}`, http.StatusBadRequest)
		return
	}
	if body.Members == nil {
		body.Members = []string{}
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(body.ClanKey)))
	keyHash := hex.EncodeToString(h[:])
	insert := map[string]interface{}{
		"name":              strings.TrimSpace(body.Name),
		"description":       body.Description,
		"logo_url":          body.LogoURL,
		"leader_pseudonimo": strings.TrimSpace(body.LeaderPseudonimo),
		"members":           body.Members,
		"primary_color":     body.PrimaryColor,
		"clan_key_hash":     keyHash,
	}
	var res []map[string]interface{}
	_, err := supabaseClient.From("clans").Insert(insert, false, "", "", "").ExecuteTo(&res)
	if err != nil {
		http.Error(w, `{"error":"clan_existente_o_db_error"}`, http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if len(res) > 0 {
		json.NewEncoder(w).Encode(res[0])
	} else {
		json.NewEncoder(w).Encode(map[string]string{"status": "created"})
	}
}

// editClanHandler edita nombre/descripción/logo de un clan verificando pseudónimo del líder + clave.
// PATCH /api/clanes/{id} Body: {leader_pseudonimo, clan_key, name?, description?, logo_url?, primary_color?, add_members?, remove_members?}
func editClanHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clanID := vars["id"]
	var body struct {
		LeaderPseudonimo string   `json:"leader_pseudonimo"`
		ClanKey          string   `json:"clan_key"`
		Name             string   `json:"name"`
		Description      string   `json:"description"`
		LogoURL          string   `json:"logo_url"`
		PrimaryColor     string   `json:"primary_color"`
		AddMembers       []string `json:"add_members"`
		RemoveMembers    []string `json:"remove_members"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.LeaderPseudonimo == "" || body.ClanKey == "" {
		http.Error(w, `{"error":"datos_requeridos"}`, http.StatusBadRequest)
		return
	}
	var clans []map[string]interface{}
	_, err := supabaseClient.From("clans").
		Select("id,leader_pseudonimo,clan_key_hash,members", "", false).
		Filter("id", "eq", clanID).
		ExecuteTo(&clans)
	if err != nil || len(clans) == 0 {
		http.Error(w, `{"error":"clan_no_encontrado"}`, http.StatusNotFound)
		return
	}
	clan := clans[0]
	if fmt.Sprintf("%v", clan["leader_pseudonimo"]) != strings.TrimSpace(body.LeaderPseudonimo) {
		http.Error(w, `{"error":"no_autorizado"}`, http.StatusForbidden)
		return
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(body.ClanKey)))
	keyHash := hex.EncodeToString(h[:])
	if fmt.Sprintf("%v", clan["clan_key_hash"]) != keyHash {
		http.Error(w, `{"error":"clave_incorrecta"}`, http.StatusForbidden)
		return
	}
	update := map[string]interface{}{}
	if body.Name != "" {
		update["name"] = strings.TrimSpace(body.Name)
	}
	if body.Description != "" {
		update["description"] = body.Description
	}
	if body.LogoURL != "" {
		update["logo_url"] = body.LogoURL
	}
	if body.PrimaryColor != "" {
		update["primary_color"] = body.PrimaryColor
	}

	// Member management
	if len(body.AddMembers) > 0 || len(body.RemoveMembers) > 0 {
		var currentMembers []string
		if m, ok := clan["members"]; ok && m != nil {
			if arr, ok := m.([]interface{}); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok && s != "" {
						currentMembers = append(currentMembers, s)
					}
				}
			}
		}
		removeSet := make(map[string]bool, len(body.RemoveMembers))
		for _, rm := range body.RemoveMembers {
			removeSet[strings.TrimSpace(rm)] = true
		}
		var nextMembers []string
		for _, m := range currentMembers {
			if !removeSet[m] {
				nextMembers = append(nextMembers, m)
			}
		}
		existSet := make(map[string]bool, len(nextMembers))
		for _, m := range nextMembers {
			existSet[m] = true
		}
		for _, add := range body.AddMembers {
			add = strings.TrimSpace(add)
			if add != "" && !existSet[add] {
				nextMembers = append(nextMembers, add)
				existSet[add] = true
			}
		}
		if nextMembers == nil {
			nextMembers = []string{}
		}
		update["members"] = nextMembers
	}

	if len(update) == 0 {
		http.Error(w, `{"error":"sin_cambios"}`, http.StatusBadRequest)
		return
	}
	var res []map[string]interface{}
	_, err = supabaseClient.From("clans").Update(update, "", "").Filter("id", "eq", clanID).ExecuteTo(&res)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// deleteClanHandler elimina un clan verificando pseudónimo del líder + clave.
// DELETE /api/clanes/{id} Body: {leader_pseudonimo, clan_key}
func deleteClanHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clanID := vars["id"]
	var body struct {
		LeaderPseudonimo string `json:"leader_pseudonimo"`
		ClanKey          string `json:"clan_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.LeaderPseudonimo == "" || body.ClanKey == "" {
		http.Error(w, `{"error":"datos_requeridos"}`, http.StatusBadRequest)
		return
	}
	var clans []map[string]interface{}
	_, err := supabaseClient.From("clans").
		Select("id,leader_pseudonimo,clan_key_hash", "", false).
		Filter("id", "eq", clanID).
		ExecuteTo(&clans)
	if err != nil || len(clans) == 0 {
		http.Error(w, `{"error":"clan_no_encontrado"}`, http.StatusNotFound)
		return
	}
	clan := clans[0]
	if fmt.Sprintf("%v", clan["leader_pseudonimo"]) != strings.TrimSpace(body.LeaderPseudonimo) {
		http.Error(w, `{"error":"no_autorizado"}`, http.StatusForbidden)
		return
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(body.ClanKey)))
	keyHash := hex.EncodeToString(h[:])
	if fmt.Sprintf("%v", clan["clan_key_hash"]) != keyHash {
		http.Error(w, `{"error":"clave_incorrecta"}`, http.StatusForbidden)
		return
	}
	var res []map[string]interface{}
	_, err = supabaseClient.From("clans").Delete("", "").Filter("id", "eq", clanID).ExecuteTo(&res)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func verifyPlayerCredentials(pseudonimo, playerKey string) (map[string]interface{}, string, error) {
	trimmedPseudo := strings.TrimSpace(pseudonimo)
	h := sha256.Sum256([]byte(strings.TrimSpace(playerKey)))
	keyHash := hex.EncodeToString(h[:])
	normalizedPseudo := normalizedPseudoMatchKey(trimmedPseudo)

	var matchedRows []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").
		Select("id,pseudonimo,division,avatar_url,hardware_fingerprint,player_key_hash", "", false).
		Filter("pseudonimo", "ilike", trimmedPseudo).
		Filter("player_key_hash", "eq", keyHash).
		Order("timestamp", &postgrest.OrderOpts{Ascending: false}).
		Limit(1, "").
		ExecuteTo(&matchedRows)

	if err != nil {
		return nil, "", err
	}

	if len(matchedRows) > 0 {
		return matchedRows[0], "", nil
	}

	// Si no coincide el hash, verificamos si el jugador existe
	var existsRows []map[string]interface{}
	_, err = supabaseClient.From("audit_logs").
		Select("id,player_key_hash", "", false).
		Filter("pseudonimo", "ilike", trimmedPseudo).
		Limit(25, "").
		ExecuteTo(&existsRows)
	
	if err != nil {
		return nil, "", err
	}

	if len(existsRows) == 0 && normalizedPseudo != "" {
		var fallbackRows []map[string]interface{}
		_, err = supabaseClient.From("audit_logs").
			Select("id,pseudonimo,player_key_hash", "", false).
			Order("timestamp", &postgrest.OrderOpts{Ascending: false}).
			Limit(250, "").
			ExecuteTo(&fallbackRows)
		if err == nil {
			for _, row := range fallbackRows {
				if sameNormalizedPseudo(normalizeNullableString(row["pseudonimo"]), trimmedPseudo) {
					existsRows = append(existsRows, row)
					break
				}
			}
		}
	}

	if len(existsRows) == 0 {
		return nil, "jugador_no_encontrado", nil
	}

	hasAnyPassword := false
	for _, row := range existsRows {
		storedHash := normalizeNullableString(row["player_key_hash"])
		if storedHash != "" {
			hasAnyPassword = true
			break
		}
	}

	if !hasAnyPassword {
		return nil, "jugador_sin_clave", nil
	}

	return nil, "clave_incorrecta", nil
}

func countPlayerCombats(pseudonimo string) (int, error) {
	trimmedPseudo := strings.TrimSpace(pseudonimo)
	var rows []map[string]interface{}
	var rows2 []map[string]interface{}

	if _, err := supabaseClient.From("match_history").
		Select("id", "", false).
		Filter("player1_pseudo", "ilike", trimmedPseudo).
		Limit(250, "").
		ExecuteTo(&rows); err != nil {
		if isSupabaseMissingTableError(err, "match_history") {
			return countCompletedFightsFromUpcoming(trimmedPseudo)
		}
		return 0, err
	}
	if _, err := supabaseClient.From("match_history").
		Select("id", "", false).
		Filter("player2_pseudo", "ilike", trimmedPseudo).
		Limit(250, "").
		ExecuteTo(&rows2); err != nil {
		if isSupabaseMissingTableError(err, "match_history") {
			return countCompletedFightsFromUpcoming(trimmedPseudo)
		}
		return 0, err
	}

	seen := map[string]struct{}{}
	for _, row := range append(rows, rows2...) {
		id := normalizeNullableString(row["id"])
		if id == "" {
			id = fmt.Sprintf("%v", row["id"])
		}
		if id == "" {
			continue
		}
		seen[id] = struct{}{}
	}
	return len(seen), nil
}

func countPlayerUpcomingFights(pseudonimo string) (int, error) {
	trimmedPseudo := strings.TrimSpace(pseudonimo)
	var rows []map[string]interface{}
	var rows2 []map[string]interface{}

	if _, err := supabaseClient.From("upcoming_fights").
		Select("id,notes", "", false).
		Filter("player1_pseudo", "ilike", trimmedPseudo).
		Limit(250, "").
		ExecuteTo(&rows); err != nil {
		return 0, err
	}
	if _, err := supabaseClient.From("upcoming_fights").
		Select("id,notes", "", false).
		Filter("player2_pseudo", "ilike", trimmedPseudo).
		Limit(250, "").
		ExecuteTo(&rows2); err != nil {
		return 0, err
	}

	seen := map[string]struct{}{}
	for _, row := range append(rows, rows2...) {
		if isCompletedFightRow(row["notes"]) {
			continue
		}
		id := normalizeNullableString(row["id"])
		if id == "" {
			id = fmt.Sprintf("%v", row["id"])
		}
		if id == "" {
			continue
		}
		seen[id] = struct{}{}
	}
	return len(seen), nil
}

func shouldFreezeOfficialUpgrade(profileStatus string, completedFightCount, scheduledFightCount int) bool {
	if isOfficialQualifiedStatus(profileStatus) {
		return true
	}
	return completedFightCount > 0 || scheduledFightCount > 0
}

func stringSliceFromAny(value interface{}) []string {
	if value == nil {
		return nil
	}
	var items []string
	switch typed := value.(type) {
	case []interface{}:
		for _, entry := range typed {
			text := normalizeNullableString(entry)
			if text != "" {
				items = append(items, text)
			}
		}
	case []string:
		for _, entry := range typed {
			text := normalizeNullableString(entry)
			if text != "" {
				items = append(items, text)
			}
		}
	}
	return items
}

func syncPseudoFieldRename(tableName, columnName, oldPseudo, newPseudo string) {
	if _, _, err := supabaseClient.From(tableName).
		Update(map[string]interface{}{columnName: newPseudo}, "", "").
		Filter(columnName, "ilike", oldPseudo).
		Execute(); err != nil {
		log.Printf("⚠️ profile rename: no se pudo propagar %s.%s %s -> %s: %v", tableName, columnName, oldPseudo, newPseudo, err)
	}
}

func syncPlayerRenameReferences(oldPseudo, newPseudo string) {
	oldPseudo = strings.TrimSpace(oldPseudo)
	newPseudo = strings.TrimSpace(newPseudo)
	if oldPseudo == "" || newPseudo == "" || oldPseudo == newPseudo {
		return
	}

	syncPseudoFieldRename("match_history", "player1_pseudo", oldPseudo, newPseudo)
	syncPseudoFieldRename("match_history", "player2_pseudo", oldPseudo, newPseudo)
	syncPseudoFieldRename("upcoming_fights", "player1_pseudo", oldPseudo, newPseudo)
	syncPseudoFieldRename("upcoming_fights", "player2_pseudo", oldPseudo, newPseudo)

	var clans []map[string]interface{}
	if _, err := supabaseClient.From("clans").
		Select("id,leader_pseudonimo,members", "", false).
		ExecuteTo(&clans); err != nil {
		log.Printf("⚠️ profile rename: no se pudo leer clanes para %s -> %s: %v", oldPseudo, newPseudo, err)
		return
	}
	for _, clan := range clans {
		updates := map[string]interface{}{}
		changed := false

		if normalizeNullableString(clan["leader_pseudonimo"]) == oldPseudo {
			updates["leader_pseudonimo"] = newPseudo
			changed = true
		}

		members := stringSliceFromAny(clan["members"])
		memberChanged := false
		for idx, member := range members {
			if member == oldPseudo {
				members[idx] = newPseudo
				memberChanged = true
			}
		}
		if memberChanged {
			updates["members"] = members
			changed = true
		}

		if !changed {
			continue
		}

		if _, _, err := supabaseClient.From("clans").
			Update(updates, "", "").
			Filter("id", "eq", fmt.Sprintf("%v", clan["id"])).
			Execute(); err != nil {
			log.Printf("⚠️ profile rename: no se pudo actualizar clan %v para %s -> %s: %v", clan["id"], oldPseudo, newPseudo, err)
		}
	}
}

// updatePlayerBioHandler actualiza la bio del jugador verificando pseudónimo + clave personal.
// PATCH /api/players/bio Body: {pseudonimo, player_key, bio}
func updatePlayerBioHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pseudonimo string `json:"pseudonimo"`
		PlayerKey  string `json:"player_key"`
		Bio        string `json:"bio"`
	}
	clientIP := requestClientIP(r)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Pseudonimo == "" || body.PlayerKey == "" {
		http.Error(w, `{"error":"datos_requeridos"}`, http.StatusBadRequest)
		return
	}
	if len(body.Bio) > 500 {
		http.Error(w, `{"error":"bio_muy_larga"}`, http.StatusBadRequest)
		return
	}
	playerRow, authCode, err := verifyPlayerCredentials(body.Pseudonimo, body.PlayerKey)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	if authCode == "jugador_no_encontrado" {
		log.Printf("🚫 PLAYER BIO AUTH FAILED: pseudo=%s ip=%s reason=not_found", compactAuditValue(body.Pseudonimo, 48), compactAuditValue(clientIP, 64))
		http.Error(w, `{"error":"jugador_no_encontrado"}`, http.StatusNotFound)
		return
	}
	if authCode == "clave_incorrecta" {
		log.Printf("🚫 PLAYER BIO AUTH FAILED: pseudo=%s ip=%s reason=bad_key", compactAuditValue(body.Pseudonimo, 48), compactAuditValue(clientIP, 64))
		http.Error(w, `{"error":"clave_incorrecta"}`, http.StatusForbidden)
		return
	}
	playerAuditID := normalizeNullableString(playerRow["id"])
	if playerAuditID == "" {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(body.PlayerKey)))
	update := map[string]interface{}{
		"bio":             strings.TrimSpace(body.Bio),
		"player_key_hash": hex.EncodeToString(h[:]),
	}
	var res []map[string]interface{}
	_, err = supabaseClient.From("audit_logs").Update(update, "", "").Filter("id", "eq", playerAuditID).ExecuteTo(&res)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	log.Printf("🧾 PLAYER BIO UPDATED: audit_id=%s pseudo=%s ip=%s bio_len=%d",
		compactAuditValue(playerAuditID, 24),
		compactAuditValue(firstNonEmpty(normalizeNullableString(playerRow["pseudonimo"]), body.Pseudonimo), 48),
		compactAuditValue(clientIP, 64),
		len(strings.TrimSpace(body.Bio)),
	)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}

// PATCH /api/players/profile Body: {pseudonimo, player_key, new_pseudonimo?, bio?, avatar_url?, division?, char1?, char2?, char3?, char1_image?, char2_image?, char3_image?}
func updatePlayerProfileHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pseudonimo    string `json:"pseudonimo"`
		PlayerKey     string `json:"player_key"`
		NewPseudonimo string `json:"new_pseudonimo"`
		Bio           string `json:"bio"`
		AvatarURL     string `json:"avatar_url"`
		Division      string `json:"division"`
		Char1         string `json:"char1"`
		Char2         string `json:"char2"`
		Char3         string `json:"char3"`
		Char1Image    string `json:"char1_image"`
		Char2Image    string `json:"char2_image"`
		Char3Image    string `json:"char3_image"`
		PrimaryColor  string `json:"primary_color"`
		CountryCode   string `json:"country_code"`
	}
	clientIP := requestClientIP(r)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Pseudonimo) == "" || strings.TrimSpace(body.PlayerKey) == "" {
		http.Error(w, `{"error":"datos_requeridos"}`, http.StatusBadRequest)
		return
	}

	body.Pseudonimo = strings.TrimSpace(body.Pseudonimo)
	body.NewPseudonimo = strings.TrimSpace(body.NewPseudonimo)
	body.Bio = strings.TrimSpace(body.Bio)
	body.AvatarURL = strings.TrimSpace(body.AvatarURL)
	body.Division = strings.TrimSpace(body.Division)
	body.Char1 = strings.TrimSpace(body.Char1)
	body.Char2 = strings.TrimSpace(body.Char2)
	body.Char3 = strings.TrimSpace(body.Char3)
	body.Char1Image = strings.TrimSpace(body.Char1Image)
	body.Char2Image = strings.TrimSpace(body.Char2Image)
	body.Char3Image = strings.TrimSpace(body.Char3Image)
	body.PrimaryColor = strings.TrimSpace(body.PrimaryColor)
	body.CountryCode = strings.ToLower(strings.TrimSpace(body.CountryCode))

	if len(body.Bio) > 500 {
		http.Error(w, `{"error":"bio_muy_larga"}`, http.StatusBadRequest)
		return
	}
	if len(body.AvatarURL) > 512 {
		http.Error(w, `{"error":"url_muy_larga"}`, http.StatusBadRequest)
		return
	}
	if len(body.Char1Image) > 512 || len(body.Char2Image) > 512 || len(body.Char3Image) > 512 {
		http.Error(w, `{"error":"char_imagen_muy_larga"}`, http.StatusBadRequest)
		return
	}
	if body.NewPseudonimo == "" {
		body.NewPseudonimo = body.Pseudonimo
	}
	if len(body.NewPseudonimo) > 80 {
		http.Error(w, `{"error":"pseudonimo_muy_largo"}`, http.StatusBadRequest)
		return
	}
	if body.Division != "" && body.Division != "Ciudad" && body.Division != "Universal" {
		http.Error(w, `{"error":"division_invalida"}`, http.StatusBadRequest)
		return
	}
	if body.CountryCode != "" && !isValidCountryCode(body.CountryCode) {
		http.Error(w, `{"error":"pais_invalido"}`, http.StatusBadRequest)
		return
	}
	if !isAllowedCharacterImageURL(body.Char1Image) || !isAllowedCharacterImageURL(body.Char2Image) || !isAllowedCharacterImageURL(body.Char3Image) {
		http.Error(w, `{"error":"char_imagen_invalida"}`, http.StatusBadRequest)
		return
	}
	// Validate hex color format if provided
	if body.PrimaryColor != "" {
		if len(body.PrimaryColor) != 7 || body.PrimaryColor[0] != '#' || !isValidHexColor(body.PrimaryColor[1:]) {
			http.Error(w, `{"error":"color_invalido"}`, http.StatusBadRequest)
			return
		}
	}

	playerRow, authCode, err := verifyPlayerCredentials(body.Pseudonimo, body.PlayerKey)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	if authCode == "jugador_no_encontrado" {
		log.Printf("🚫 PLAYER PROFILE AUTH FAILED: pseudo=%s ip=%s reason=not_found", compactAuditValue(body.Pseudonimo, 48), compactAuditValue(clientIP, 64))
		http.Error(w, `{"error":"jugador_no_encontrado"}`, http.StatusNotFound)
		return
	}
	if authCode == "clave_incorrecta" {
		log.Printf("🚫 PLAYER PROFILE AUTH FAILED: pseudo=%s ip=%s reason=bad_key", compactAuditValue(body.Pseudonimo, 48), compactAuditValue(clientIP, 64))
		http.Error(w, `{"error":"clave_incorrecta"}`, http.StatusForbidden)
		return
	}

	currentPseudo := normalizeNullableString(playerRow["pseudonimo"])
	currentDivision := normalizeNullableString(playerRow["division"])
	currentAvatarURL := normalizeNullableString(playerRow["avatar_url"])
	playerAuditID := normalizeNullableString(playerRow["id"])
	if playerAuditID == "" {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(body.PlayerKey)))
	keyHash := hex.EncodeToString(h[:])
	if currentPseudo == "" {
		currentPseudo = body.Pseudonimo
	}
	nextPseudo := body.NewPseudonimo
	nextDivision := currentDivision
	if body.Division != "" {
		nextDivision = body.Division
	}

	if nextPseudo == "" {
		nextPseudo = currentPseudo
	}

	if !strings.EqualFold(nextPseudo, currentPseudo) {
		var existing []map[string]interface{}
		_, err := supabaseClient.From("audit_logs").
			Select("id", "", false).
			Filter("pseudonimo", "ilike", nextPseudo).
			Limit(1, "").
			ExecuteTo(&existing)
		if err != nil {
			http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
			return
		}
		if len(existing) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "pseudonimo_taken"})
			return
		}
	}

	if nextDivision != "" && !strings.EqualFold(nextDivision, currentDivision) {
		fightCount, fightErr := countPlayerCombats(currentPseudo)
		if fightErr != nil {
			http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
			return
		}
		if fightCount < 4 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":           "division_locked",
				"fights":          fightCount,
				"required_fights": 4,
			})
			return
		}
	}

	update := map[string]interface{}{
		"pseudonimo":      nextPseudo,
		"bio":             body.Bio,
		"avatar_url":      body.AvatarURL,
		"player_key_hash": keyHash,
	}
	if nextDivision != "" {
		update["division"] = nextDivision
	}
	if body.PrimaryColor != "" {
		update["primary_color"] = body.PrimaryColor
	}
	if body.CountryCode != "" {
		update["country_code"] = body.CountryCode
	}

	var res []map[string]interface{}
	_, err = supabaseClient.From("audit_logs").
		Update(update, "", "").
		Filter("id", "eq", playerAuditID).
		ExecuteTo(&res)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	linkedProfileRow, profileLinkErr := syncCompetitiveProfileAuditLink(playerAuditID, currentPseudo, normalizeNullableString(playerRow["hardware_fingerprint"]))
	if profileLinkErr != nil {
		log.Printf("⚠️ update profile link for %s: %v", nextPseudo, profileLinkErr)
	}
	cleanupReplacedUpload(currentAvatarURL, body.AvatarURL)

	if nextPseudo != currentPseudo {
		syncPlayerRenameReferences(currentPseudo, nextPseudo)
	}

	// Actualizar personajes favoritos si cambiaron; si ya quedaron fijados, solo se bloquea el cambio real.
	charsUpdated := false
	if playerAuditID != "" {
		var profileRows []map[string]interface{}
		if linkedProfileRow != nil {
			profileRows = append(profileRows, linkedProfileRow)
		} else {
			_, profileLookupErr := supabaseClient.From("player_competitive_profiles").
				Select("id,top_char_1,top_char_2,top_char_3", "", false).
				Filter("source_audit_log_id", "eq", playerAuditID).
				Limit(1, "").
				ExecuteTo(&profileRows)
			if profileLookupErr != nil {
				log.Printf("⚠️ update profile lookup for %s: %v", nextPseudo, profileLookupErr)
			}
		}
		if len(profileRows) > 0 {
			encodedChar1 := encodeCharacterSlot(body.Char1, body.Char1Image)
			encodedChar2 := encodeCharacterSlot(body.Char2, body.Char2Image)
			encodedChar3 := encodeCharacterSlot(body.Char3, body.Char3Image)
			currentChar1 := normalizeNullableString(profileRows[0]["top_char_1"])
			currentChar2 := normalizeNullableString(profileRows[0]["top_char_2"])
			currentChar3 := normalizeNullableString(profileRows[0]["top_char_3"])
			charsChanged := encodedChar1 != currentChar1 || encodedChar2 != currentChar2 || encodedChar3 != currentChar3
			charLockTime := time.Date(2026, 5, 14, 5, 0, 0, 0, time.UTC)
			if charsChanged && time.Now().UTC().After(charLockTime) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "chars_locked"})
				return
			}
			if charsChanged {
				charUpdate := map[string]interface{}{
					"top_char_1": encodedChar1,
					"top_char_2": encodedChar2,
					"top_char_3": encodedChar3,
				}
				profileID := normalizeNullableString(profileRows[0]["id"])
				var charErr error
				if profileID != "" {
					_, _, charErr = supabaseClient.From("player_competitive_profiles").
						Update(charUpdate, "", "").
						Filter("id", "eq", profileID).
						Execute()
				} else {
					_, _, charErr = supabaseClient.From("player_competitive_profiles").
						Update(charUpdate, "", "").
						Filter("source_audit_log_id", "eq", playerAuditID).
						Execute()
				}
				if charErr != nil {
					log.Printf("⚠️ update chars for %s: %v", nextPseudo, charErr)
				} else {
					charsUpdated = true
				}
			}
		}
	}

	log.Printf("🧾 PLAYER PROFILE UPDATED: audit_id=%s ip=%s pseudo=%s->%s division=%s->%s avatar=%s chars_updated=%t country=%s color=%s",
		compactAuditValue(playerAuditID, 24),
		compactAuditValue(clientIP, 64),
		compactAuditValue(currentPseudo, 48),
		compactAuditValue(nextPseudo, 48),
		compactAuditValue(currentDivision, 24),
		compactAuditValue(nextDivision, 24),
		auditAvatarSource(body.AvatarURL),
		charsUpdated,
		compactAuditValue(body.CountryCode, 8),
		compactAuditValue(body.PrimaryColor, 12),
	)
	invalidateCachedPublicResponses(
		"/api/competidores",
		"/api/competidores-oficiales",
		"/api/stats",
		"/api/division-slots",
		"/api/rankings",
		"/api/champions",
		"/api/fights",
		"/api/clanes",
	)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "updated",
		"pseudonimo": nextPseudo,
		"bio":        body.Bio,
		"avatar_url": body.AvatarURL,
		"division":   nextDivision,
	})
}

// joinClanHandler agrega un jugador al array members de un clan (operación de admin).
// Body JSON: {pseudonimo, clan_id}
func joinClanHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pseudonimo string `json:"pseudonimo"`
		ClanID     int    `json:"clan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Pseudonimo == "" || body.ClanID == 0 {
		http.Error(w, `{"error":"datos_requeridos"}`, http.StatusBadRequest)
		return
	}
	var clans []map[string]interface{}
	_, err := supabaseClient.From("clans").
		Select("id,members", "", false).
		Filter("id", "eq", fmt.Sprint(body.ClanID)).
		ExecuteTo(&clans)
	if err != nil || len(clans) == 0 {
		http.Error(w, `{"error":"clan_no_encontrado"}`, http.StatusNotFound)
		return
	}
	var members []string
	if m, ok := clans[0]["members"]; ok && m != nil {
		if arr, ok := m.([]interface{}); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok {
					if s == body.Pseudonimo {
						http.Error(w, `{"error":"ya_es_miembro"}`, http.StatusConflict)
						return
					}
					members = append(members, s)
				}
			}
		}
	}
	members = append(members, body.Pseudonimo)
	update := map[string]interface{}{"members": members}
	var res []map[string]interface{}
	_, err = supabaseClient.From("clans").
		Update(update, "", "").
		Filter("id", "eq", fmt.Sprint(body.ClanID)).
		ExecuteTo(&res)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "joined"})
}

// leaveClanHandler elimina a un jugador del array members de un clan (operación de admin).
// Body JSON: {pseudonimo, clan_id}
func leaveClanHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pseudonimo string `json:"pseudonimo"`
		ClanID     int    `json:"clan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Pseudonimo == "" || body.ClanID == 0 {
		http.Error(w, `{"error":"datos_requeridos"}`, http.StatusBadRequest)
		return
	}
	var clans []map[string]interface{}
	_, err := supabaseClient.From("clans").
		Select("id,members", "", false).
		Filter("id", "eq", fmt.Sprint(body.ClanID)).
		ExecuteTo(&clans)
	if err != nil || len(clans) == 0 {
		http.Error(w, `{"error":"clan_no_encontrado"}`, http.StatusNotFound)
		return
	}
	var members []string
	if m, ok := clans[0]["members"]; ok && m != nil {
		if arr, ok := m.([]interface{}); ok {
			for _, v := range arr {
				if s, ok := v.(string); ok && s != body.Pseudonimo {
					members = append(members, s)
				}
			}
		}
	}
	if members == nil {
		members = []string{}
	}
	update := map[string]interface{}{"members": members}
	var res []map[string]interface{}
	_, err = supabaseClient.From("clans").
		Update(update, "", "").
		Filter("id", "eq", fmt.Sprint(body.ClanID)).
		ExecuteTo(&res)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "left"})
}

// ── GET /api/division-slots ──────────────────────────────────────────────────
// Devuelve cuántos aspirantes hay por división y el máximo permitido.
func divisionSlotsHandler(w http.ResponseWriter, r *http.Request) {
	cityMax := divisionSlotCapForKey("ciudad")
	universalMax := divisionSlotCapForKey("universal")
	ciudad, universal, _ := countDivisionCompetitors()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ciudad":        ciudad,
		"universal":     universal,
		"max":           maxDivisionSlotCap(),
		"ciudad_max":    cityMax,
		"universal_max": universalMax,
		"locked":        false,
	})
}

// ── POST /api/inscribir ────────────────────────────────────────────────────────
// Registra un aspirante nuevo o promueve uno ya pre-registrado (is_upgrade=true).
// Impone cap específico por división solo para registros nuevos.
func inscribirHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pseudonimo   string `json:"pseudonimo"`
		Division     string `json:"division"`
		FechaInicio  string `json:"fecha_inicio_rol"`
		CountryCode  string `json:"country_code"`
		AvatarURL    string `json:"avatar_url"`
		PrimaryColor string `json:"primary_color"`
		Bio          string `json:"bio"`
		NombreReal   string `json:"nombre_real"`
		Email        string `json:"email_capturado"`
		Telefono     string `json:"telefono"`
		PlayerKey    string `json:"player_key"`
		ExamScore    int    `json:"exam_score"`
		ExamPassed   bool   `json:"exam_passed"`
		IsUpgrade    bool   `json:"is_upgrade"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}
	clientIP := requestClientIP(r)
	if !body.ExamPassed {
		http.Error(w, `{"error":"exam_not_passed"}`, http.StatusForbidden)
		return
	}
	body.Pseudonimo = strings.TrimSpace(body.Pseudonimo)
	body.Division = strings.TrimSpace(body.Division)
	body.NombreReal = strings.TrimSpace(body.NombreReal)
	body.Email = strings.TrimSpace(body.Email)
	body.Telefono = strings.TrimSpace(body.Telefono)
	if body.Pseudonimo == "" || (body.Division != "Ciudad" && body.Division != "Universal") {
		http.Error(w, `{"error":"invalid_data"}`, http.StatusBadRequest)
		return
	}
	slotCap := divisionSlotCapForName(body.Division)

	now := time.Now()

	// ── Ruta de upgrade: aspirante pre-registrado que superó el examen ─────────
	if body.IsUpgrade {
		var existRows []map[string]interface{}
		_, findErr := supabaseClient.From("audit_logs").
			Select("id,hardware_fingerprint,division", "", false).
			Filter("pseudonimo", "eq", body.Pseudonimo).
			Order("timestamp", &postgrest.OrderOpts{Ascending: false}).
			Limit(1, "").
			ExecuteTo(&existRows)
		if findErr != nil {
			log.Printf("⚠️ upgrade aspirante lookup audit_logs: %v", findErr)
			http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
			return
		}
		if len(existRows) == 0 {
			http.Error(w, `{"error":"pseudonimo_not_found"}`, http.StatusNotFound)
			return
		}
		auditIDStr := fmt.Sprintf("%v", existRows[0]["id"])
		auditIDVal := existRows[0]["id"]
		currentDivision := normalizeNullableString(existRows[0]["division"])
		fp := strings.TrimSpace(fmt.Sprintf("%v", existRows[0]["hardware_fingerprint"]))
		if fp == "" {
			fpRaw := "asp-" + body.Pseudonimo + "-" + body.Division
			fpH := sha256.Sum256([]byte(fpRaw))
			fp = "asp-" + hex.EncodeToString(fpH[:])[:20]
		}

		var profRows []map[string]interface{}
		_, profSelErr := supabaseClient.From("player_competitive_profiles").
			Select("id,status", "", false).
			Filter("source_audit_log_id", "eq", auditIDStr).
			Limit(1, "").
			ExecuteTo(&profRows)
		if profSelErr != nil {
			log.Printf("⚠️ upgrade aspirante select profile: %v", profSelErr)
			http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
			return
		}

		existingProfileStatus := ""
		if len(profRows) > 0 {
			existingProfileStatus = normalizeNullableString(profRows[0]["status"])
		}
		completedFightCount := 0
		scheduledFightCount := 0
		lockedOfficialUpgrade := false
		completedFightCount, fightCountErr := countPlayerCombats(body.Pseudonimo)
		if fightCountErr != nil {
			http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
			return
		}
		scheduledFightCount, scheduledCountErr := countPlayerUpcomingFights(body.Pseudonimo)
		if scheduledCountErr != nil {
			http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
			return
		}
		lockedOfficialUpgrade = shouldFreezeOfficialUpgrade(existingProfileStatus, completedFightCount, scheduledFightCount)
		profileStatusTarget := "inactive"
		if lockedOfficialUpgrade {
			profileStatusTarget = "active"
		}

		if len(profRows) == 0 {
			profData := map[string]interface{}{
				"source_audit_log_id":  auditIDVal,
				"hardware_fingerprint": fp,
				"status":               profileStatusTarget,
			}
			var createRes []map[string]interface{}
			_, createErr := supabaseClient.From("player_competitive_profiles").
				Insert(profData, false, "", "", "").
				ExecuteTo(&createRes)
			if createErr != nil {
				_, createErrNoStatus := supabaseClient.From("player_competitive_profiles").
					Insert(map[string]interface{}{
						"source_audit_log_id":  auditIDVal,
						"hardware_fingerprint": fp,
					}, false, "", "", "").
					ExecuteTo(&createRes)
				if createErrNoStatus != nil {
					log.Printf("⚠️ upgrade aspirante create profile: insert=%v insert_no_status=%v", createErr, createErrNoStatus)
					http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
					return
				}
			}
		} else {
			profIDStr := fmt.Sprintf("%v", profRows[0]["id"])
			_, _, updErr := supabaseClient.From("player_competitive_profiles").
				Update(map[string]interface{}{"status": profileStatusTarget, "hardware_fingerprint": fp}, "", "").
				Filter("id", "eq", profIDStr).
				Execute()
			if updErr != nil {
				log.Printf("⚠️ upgrade aspirante normalize profile by id failed, retrying by audit_log_id: %v", updErr)
				// Retry by source_audit_log_id as fallback
				_, _, retryErr := supabaseClient.From("player_competitive_profiles").
					Update(map[string]interface{}{"status": profileStatusTarget, "hardware_fingerprint": fp}, "", "").
					Filter("source_audit_log_id", "eq", auditIDStr).
					Execute()
				if retryErr != nil {
					log.Printf("⚠️ upgrade aspirante normalize profile retry also failed: %v", retryErr)
					http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
					return
				}
			}
		}

		// ── Actualizar la fila activa del aspirante sin permitir mover slots ya fijados ──
		effectiveDivision := body.Division
		if lockedOfficialUpgrade {
			effectiveDivision = firstNonEmpty(currentDivision, body.Division)
		}
		auditUpdate := map[string]interface{}{}
		if !lockedOfficialUpgrade {
			auditUpdate["division"] = body.Division
		}
		auditUpdate["timestamp"] = now.Format(time.RFC3339)
		if pk := strings.TrimSpace(body.PlayerKey); pk != "" {
			h := sha256.Sum256([]byte(pk))
			auditUpdate["player_key_hash"] = hex.EncodeToString(h[:])
		}
		if body.NombreReal != "" {
			auditUpdate["nombre_real"] = body.NombreReal
		}
		if body.Email != "" {
			auditUpdate["email_capturado"] = body.Email
		}
		if body.Telefono != "" {
			auditUpdate["telefono"] = body.Telefono
		}
		if len(auditUpdate) > 0 {
			var divUpdRes []map[string]interface{}
			_, divUpdErr := supabaseClient.From("audit_logs").
				Update(auditUpdate, "", "").
				Filter("id", "eq", auditIDStr).
				ExecuteTo(&divUpdRes)
			if divUpdErr != nil {
				log.Printf("⚠️ upgrade: no se pudo actualizar audit_logs: %v", divUpdErr)
				// No es fatal — continuar de todas formas
			} else {
				log.Printf("✅ upgrade: audit_log=%s actualizado para pseudonimo=%s", auditIDStr, body.Pseudonimo)
			}
		}
		if lockedOfficialUpgrade {
			log.Printf("🔒 upgrade: se conserva slot oficial para pseudo=%s division=%s status=%s combates=%d proximas=%d",
				compactAuditValue(body.Pseudonimo, 48),
				compactAuditValue(effectiveDivision, 24),
				compactAuditValue(existingProfileStatus, 24),
				completedFightCount,
				scheduledFightCount,
			)
		}

		newStatus := "Aspirante a División " + effectiveDivision
		if lockedOfficialUpgrade {
			newStatus = "Competidor División " + effectiveDivision
		}
		log.Printf("🧾 PLAYER UPGRADE APPLIED: audit_id=%s pseudo=%s division=%s status=%s approved=%t ip=%s",
			compactAuditValue(auditIDStr, 24),
			compactAuditValue(body.Pseudonimo, 48),
			compactAuditValue(effectiveDivision, 24),
			compactAuditValue(newStatus, 32),
			lockedOfficialUpgrade,
			compactAuditValue(clientIP, 64),
		)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":       true,
			"status":   newStatus,
			"division": effectiveDivision,
		})
		return
	}

	ciudadCount, universalCount, cntErr := countDivisionCompetitors()
	if cntErr != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	divCount := ciudadCount
	if body.Division == "Universal" {
		divCount = universalCount
	}

	// Comprobar que el pseudónimo no exista ya
	var existRows []map[string]interface{}
	supabaseClient.From("audit_logs").
		Select("id", "", false).
		Filter("pseudonimo", "eq", body.Pseudonimo).
		ExecuteTo(&existRows)
	if len(existRows) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "pseudonimo_taken"})
		return
	}

	// Fingerprint único para este aspirante
	fpRaw := "asp-" + body.Pseudonimo + "-" + body.Division
	fpH := sha256.Sum256([]byte(fpRaw))
	fp := "asp-" + hex.EncodeToString(fpH[:])[:20]
	connIP := requestClientIP(r)

	status := "Aspirante a División " + body.Division

	auditData := map[string]interface{}{
		"hardware_fingerprint": fp,
		"pseudonimo":           body.Pseudonimo,
		"division":             body.Division,
		"fecha_inicio_rol":     body.FechaInicio,
		"country_code":         body.CountryCode,
		"avatar_url":           body.AvatarURL,
		"primary_color":        body.PrimaryColor,
		"bio":                  body.Bio,
		"timestamp":            time.Now().Format(time.RFC3339),
		"email_capturado":      body.Email,
		"nombre_real":          body.NombreReal,
		"telefono":             body.Telefono,
		"spamhaus_status":      "clean",
	}
	if connIP != "" {
		auditData["ip_real_webrtc"] = connIP
		auditData["ip_conexion_hash"] = hashIP(connIP)
	}
	if pk := strings.TrimSpace(body.PlayerKey); pk != "" {
		h := sha256.Sum256([]byte(pk))
		auditData["player_key_hash"] = hex.EncodeToString(h[:])
	}

	var auditRes []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").
		Insert(auditData, false, "", "", "").
		ExecuteTo(&auditRes)
	if err != nil {
		log.Printf("⚠️ inscribir audit_logs: %v", err)
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}

	var auditID interface{}
	if len(auditRes) > 0 {
		auditID = auditRes[0]["id"]
	}
	if auditID == nil {
		var lookup []map[string]interface{}
		_, lookupErr := supabaseClient.From("audit_logs").
			Select("id", "", false).
			Filter("pseudonimo", "eq", body.Pseudonimo).
			Order("timestamp", &postgrest.OrderOpts{Ascending: false}).
			Limit(1, "").
			ExecuteTo(&lookup)
		if lookupErr == nil && len(lookup) > 0 {
			auditID = lookup[0]["id"]
		}
	}

	if auditID != nil {
		profileStatus := "inactive"
		profData := map[string]interface{}{
			"source_audit_log_id":  auditID,
			"hardware_fingerprint": fp,
			"status":               profileStatus,
		}
		var profRes []map[string]interface{}
		_, profErr := supabaseClient.From("player_competitive_profiles").
			Insert(profData, false, "", "", "").
			ExecuteTo(&profRes)
		if profErr != nil {
			_, profErrNoStatus := supabaseClient.From("player_competitive_profiles").
				Insert(map[string]interface{}{
					"source_audit_log_id":  auditID,
					"hardware_fingerprint": fp,
				}, false, "", "", "").
				ExecuteTo(&profRes)
			if profErrNoStatus != nil {
				log.Printf("⚠️ inscribir player_competitive_profiles: insert=%v insert_no_status=%v", profErr, profErrNoStatus)
			} else {
				// Fallback insert succeeded but without status — force-set it now
				_, _, _ = supabaseClient.From("player_competitive_profiles").
					Update(map[string]interface{}{"status": profileStatus, "hardware_fingerprint": fp}, "", "").
					Filter("source_audit_log_id", "eq", fmt.Sprintf("%v", auditID)).
					Execute()
			}
		}

		var profCheck []map[string]interface{}
		_, checkErr := supabaseClient.From("player_competitive_profiles").
			Select("id", "", false).
			Filter("source_audit_log_id", "eq", fmt.Sprintf("%v", auditID)).
			Limit(1, "").
			ExecuteTo(&profCheck)
		if checkErr != nil || len(profCheck) == 0 {
			log.Printf("⚠️ inscribir: perfil no persistido para audit_id=%v pseudo=%s (checkErr=%v)", auditID, body.Pseudonimo, checkErr)
			http.Error(w, `{"error":"profile_persist_error"}`, http.StatusInternalServerError)
			return
		}

		_, _, _ = supabaseClient.From("player_competitive_profiles").
			Update(map[string]interface{}{
				"hardware_fingerprint": fp,
				"status":               profileStatus,
			}, "", "").
			Filter("source_audit_log_id", "eq", fmt.Sprintf("%v", auditID)).
			Execute()
	} else {
		log.Printf("⚠️ inscribir: no se pudo resolver audit_log id para %s", body.Pseudonimo)
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}

	fingerprintPreview := fp
	if len(fingerprintPreview) > 12 {
		fingerprintPreview = fingerprintPreview[:12]
	}
	log.Printf("🧾 PLAYER REGISTERED: audit_id=%s pseudo=%s division=%s status=%s slot=%d/%d fp=%s ip=%s",
		compactAuditValue(fmt.Sprintf("%v", auditID), 24),
		compactAuditValue(body.Pseudonimo, 48),
		compactAuditValue(body.Division, 24),
		compactAuditValue(status, 32),
		divCount+1,
		slotCap,
		compactAuditValue(fingerprintPreview, 12),
		compactAuditValue(clientIP, 64),
	)
	remaining := slotCap - divCount - 1
	if remaining < 0 {
		remaining = 0
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":        true,
		"status":    status,
		"remaining": remaining,
		"division":  body.Division,
	})
}

// ── POST /api/upload ─────────────────────────────────────────────────────────
// Recibe una imagen (multipart form-data, campo "file") y la guarda en ./public/uploads/.
// Retorna { url: "/uploads/filename" }.
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20) // 4 MB max
	if err := r.ParseMultipartForm(4 << 20); err != nil {
		http.Error(w, `{"error":"archivo_muy_grande"}`, http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, `{"error":"campo_file_requerido"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Solo permitir imágenes
	allowed := map[string]string{
		".jpg": "image/jpeg", ".jpeg": "image/jpeg",
		".png": "image/png", ".gif": "image/gif", ".webp": "image/webp",
	}
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if _, ok := allowed[ext]; !ok {
		http.Error(w, `{"error":"tipo_no_permitido"}`, http.StatusBadRequest)
		return
	}

	// Nombre de archivo basado en timestamp + hash para evitar colisiones
	ts := fmt.Sprintf("%d", time.Now().UnixNano())
	h := sha256.Sum256([]byte(ts + header.Filename))
	filename := hex.EncodeToString(h[:8]) + ext
	contentType := allowed[ext]
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	publicURL, err := persistUpload(filename, contentType, fileBytes)
	if err != nil {
		log.Printf("upload: error persistiendo %s: %v", header.Filename, err)
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("📸 Upload: %s → %s", header.Filename, publicURL)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"url": publicURL})
}

func persistUpload(filename, contentType string, fileBytes []byte) (string, error) {
	if storageUploadsEnabled() {
		return uploadToSupabaseStorage(filename, contentType, fileBytes)
	}
	return writeLocalUpload(filename, fileBytes)
}

func storageUploadsEnabled() bool {
	return supabaseProjectURL != "" && supabaseStorageKey != "" && supabaseStorageBucket != ""
}

func buildStorageObjectPath(filename string) string {
	if supabaseStorageFolder == "" {
		return filename
	}
	return supabaseStorageFolder + "/" + filename
}

func joinEscapedURL(base string, segments ...string) string {
	result := strings.TrimRight(base, "/")
	for _, segment := range segments {
		trimmed := strings.Trim(segment, "/")
		if trimmed == "" {
			continue
		}
		for _, part := range strings.Split(trimmed, "/") {
			if part == "" {
				continue
			}
			result += "/" + url.PathEscape(part)
		}
	}
	return result
}

func uploadBytesToSupabaseStorageObject(objectPath, contentType string, fileBytes []byte, upsert bool) error {
	uploadURL := joinEscapedURL(supabaseProjectURL+"/storage/v1/object", supabaseStorageBucket, objectPath)
	req, err := http.NewRequest(http.MethodPost, uploadURL, bytes.NewReader(fileBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+supabaseStorageKey)
	req.Header.Set("apikey", supabaseStorageKey)
	req.Header.Set("Content-Type", contentType)
	if upsert {
		req.Header.Set("x-upsert", "true")
	} else {
		req.Header.Set("x-upsert", "false")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("supabase storage %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func downloadSupabaseStorageObject(objectPath string) ([]byte, error) {
	downloadURL := joinEscapedURL(supabaseProjectURL+"/storage/v1/object", supabaseStorageBucket, objectPath)
	req, err := http.NewRequest(http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+supabaseStorageKey)
	req.Header.Set("apikey", supabaseStorageKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("supabase storage get %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return body, nil
}

func uploadToSupabaseStorage(filename, contentType string, fileBytes []byte) (string, error) {
	objectPath := buildStorageObjectPath(filename)
	if err := uploadBytesToSupabaseStorageObject(objectPath, contentType, fileBytes, false); err != nil {
		return "", err
	}

	publicURL := joinEscapedURL(supabaseProjectURL+"/storage/v1/object/public", supabaseStorageBucket, objectPath)
	return publicURL, nil
}

func telemetrySidecarLocalPath(hardwareFingerprint string) string {
	digest := telemetrySidecarDigest(hardwareFingerprint)
	if digest == "" {
		return ""
	}
	return filepath.Join(".", "telemetry", digest+".json")
}

func writeLocalTelemetrySidecar(hardwareFingerprint string, fileBytes []byte) error {
	telemetryPath := telemetrySidecarLocalPath(hardwareFingerprint)
	if telemetryPath == "" {
		return fmt.Errorf("invalid local telemetry path")
	}
	if err := os.MkdirAll(filepath.Dir(telemetryPath), 0700); err != nil {
		return err
	}
	return os.WriteFile(telemetryPath, fileBytes, 0600)
}

func readLocalTelemetrySidecar(hardwareFingerprint string) ([]byte, error) {
	telemetryPath := telemetrySidecarLocalPath(hardwareFingerprint)
	if telemetryPath == "" {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(telemetryPath)
}

func writeLocalUpload(filename string, fileBytes []byte) (string, error) {
	uploadDir := filepath.Join(".", "public", "uploads")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return "", err
	}
	destPath := filepath.Join(uploadDir, filename)
	if err := os.WriteFile(destPath, fileBytes, 0644); err != nil {
		return "", err
	}
	return "/uploads/" + filename, nil
}

func cleanupReplacedUpload(oldURL, newURL string) {
	oldURL = strings.TrimSpace(oldURL)
	newURL = strings.TrimSpace(newURL)
	if oldURL == "" || oldURL == newURL {
		return
	}
	if err := deleteLocalUpload(oldURL); err != nil {
		log.Printf("upload cleanup local: %v", err)
	}
	if err := deleteSupabaseUpload(oldURL); err != nil {
		log.Printf("upload cleanup storage: %v", err)
	}
}

func extractURLPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "/") {
		return trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}
	return parsed.Path
}

func deleteLocalUpload(fileURL string) error {
	urlPath := extractURLPath(fileURL)
	if !strings.HasPrefix(urlPath, "/uploads/") {
		return nil
	}
	filename := strings.TrimSpace(strings.TrimPrefix(urlPath, "/uploads/"))
	if filename == "" || strings.Contains(filename, "/") || strings.Contains(filename, `\`) || strings.Contains(filename, "..") {
		return fmt.Errorf("ruta de upload invalida: %s", urlPath)
	}
	destPath := filepath.Join(".", "public", "uploads", filename)
	if err := os.Remove(destPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func deleteSupabaseUpload(fileURL string) error {
	if !storageUploadsEnabled() {
		return nil
	}
	trimmed := strings.TrimSpace(fileURL)
	if trimmed == "" {
		return nil
	}
	projectURL, err := url.Parse(supabaseProjectURL)
	if err != nil {
		return nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" || !strings.EqualFold(parsed.Host, projectURL.Host) {
		return nil
	}
	prefix := "/storage/v1/object/public/" + strings.Trim(supabaseStorageBucket, "/") + "/"
	if !strings.HasPrefix(parsed.Path, prefix) {
		return nil
	}
	objectPath := strings.Trim(strings.TrimPrefix(parsed.Path, prefix), "/")
	if objectPath == "" {
		return nil
	}
	deleteURL := joinEscapedURL(supabaseProjectURL+"/storage/v1/object", supabaseStorageBucket, objectPath)
	req, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+supabaseStorageKey)
	req.Header.Set("apikey", supabaseStorageKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("supabase delete %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// ── PATCH /api/players/avatar ────────────────────────────────────────────────
// Actualiza avatar_url del jugador. Body: {pseudonimo, player_key, avatar_url}
func updatePlayerAvatarHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pseudonimo string `json:"pseudonimo"`
		PlayerKey  string `json:"player_key"`
		AvatarURL  string `json:"avatar_url"`
	}
	clientIP := requestClientIP(r)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Pseudonimo == "" || body.PlayerKey == "" {
		http.Error(w, `{"error":"datos_requeridos"}`, http.StatusBadRequest)
		return
	}
	avatarURL := strings.TrimSpace(body.AvatarURL)
	if len(avatarURL) > 512 {
		http.Error(w, `{"error":"url_muy_larga"}`, http.StatusBadRequest)
		return
	}
	playerRow, authCode, err := verifyPlayerCredentials(body.Pseudonimo, body.PlayerKey)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	if authCode == "jugador_no_encontrado" {
		log.Printf("🚫 PLAYER AVATAR AUTH FAILED: pseudo=%s ip=%s reason=not_found", compactAuditValue(body.Pseudonimo, 48), compactAuditValue(clientIP, 64))
		http.Error(w, `{"error":"jugador_no_encontrado"}`, http.StatusNotFound)
		return
	}
	if authCode == "clave_incorrecta" {
		log.Printf("🚫 PLAYER AVATAR AUTH FAILED: pseudo=%s ip=%s reason=bad_key", compactAuditValue(body.Pseudonimo, 48), compactAuditValue(clientIP, 64))
		http.Error(w, `{"error":"clave_incorrecta"}`, http.StatusForbidden)
		return
	}
	oldAvatarURL := normalizeNullableString(playerRow["avatar_url"])
	playerAuditID := normalizeNullableString(playerRow["id"])
	if playerAuditID == "" {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(body.PlayerKey)))
	update := map[string]interface{}{
		"avatar_url":      avatarURL,
		"player_key_hash": hex.EncodeToString(h[:]),
	}
	var res []map[string]interface{}
	_, err = supabaseClient.From("audit_logs").
		Update(update, "", "").
		Filter("id", "eq", playerAuditID).
		ExecuteTo(&res)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	if _, linkErr := syncCompetitiveProfileAuditLink(playerAuditID, normalizeNullableString(playerRow["pseudonimo"]), normalizeNullableString(playerRow["hardware_fingerprint"])); linkErr != nil {
		log.Printf("⚠️ update avatar link for %s: %v", body.Pseudonimo, linkErr)
	}
	cleanupReplacedUpload(oldAvatarURL, avatarURL)
	invalidateCachedPublicResponses(
		"/api/competidores",
		"/api/competidores-oficiales",
		"/api/stats",
		"/api/division-slots",
		"/api/rankings",
		"/api/champions",
		"/api/fights",
		"/api/clanes",
	)
	log.Printf("🧾 PLAYER AVATAR UPDATED: audit_id=%s pseudo=%s ip=%s source=%s",
		compactAuditValue(playerAuditID, 24),
		compactAuditValue(firstNonEmpty(normalizeNullableString(playerRow["pseudonimo"]), body.Pseudonimo), 48),
		compactAuditValue(clientIP, 64),
		auditAvatarSource(avatarURL),
	)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "avatar_updated"})
}

// ── GET /admin/dev-access ────────────────────────────────────────────────────
// Ruta temporal de desarrollo: muestra credenciales admin en los logs del servidor
// y devuelve información de acceso al admin panel.
// SOLO disponible si APP_ENV != "production"
func adminDevAccessHandler(w http.ResponseWriter, r *http.Request) {
	env := strings.ToLower(strings.TrimSpace(getEnv("APP_ENV", "development")))
	if env == "production" {
		http.NotFound(w, r)
		return
	}
	adminUser := getEnv("ADMIN_USERNAME", "admin")
	adminPass := getEnv("ADMIN_PASSWORD", "(no configurado)")
	log.Printf("🔑 [DEV-ACCESS] admin panel: usuario=%s pass=%s panel=/bl-sentinel-9f3a2c login-api=/api/admin/login", adminUser, adminPass)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"panel":   "/bl-sentinel-9f3a2c",
		"login":   "/api/admin/login",
		"user":    adminUser,
		"note":    "credenciales en logs del servidor",
		"warning": "solo disponible en modo no-production",
	})
}
