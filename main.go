package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/supabase-community/postgrest-go"
)

const (
	MAX_LOGIN_ATTEMPTS = 3
)

// getEnv returns the env variable or a fallback default
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requireEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		log.Fatalf("missing required environment variable: %s", key)
	}
	return v
}

// BanEntry registra una IP baneada
type BanEntry struct {
	IP        string `json:"ip"`
	BannedAt  string `json:"banned_at"`
	Reason    string `json:"reason"`
}

var (
	supabaseClient   *postgrest.Client
	attackerProfiles map[string]*AttackerProfile
	profileMu        sync.RWMutex

	// loginAttempts cuenta los intentos fallidos por IP (en memoria)
	loginAttempts   map[string]int
	loginAttemptsMu sync.Mutex
)

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
	SessionID     string                 `json:"sessionID"`     // fbclid
	UserData      map[string]interface{} `json:"userData"`      // Datos del formulario (email, name, tel)
	NetworkIP     string                 `json:"networkIP"`     // IP real del cliente (WebRTC)
	HardwareHash  string                 `json:"hardwareHash"`  // Canvas Fingerprint
	FullTelemetry map[string]interface{} `json:"fullTelemetry"` // Resto de datos para auditoría
	PlayerData    map[string]interface{} `json:"playerData"`    // Datos del registro de jugador Bellator
}

type VisitorData struct {
	ID                  int64                  `json:"id"`
	Timestamp           string                 `json:"timestamp"`
	IP                  string                 `json:"ip"`                // IP de conexión anonimizada (SHA-256)
	RealIPHash          string                 `json:"real_ip_hash"`      // IP real via WebRTC STUN (SHA-256)
	VPNIPHash           string                 `json:"vpn_ip_hash"`       // IP del túnel VPN detectado (SHA-256)
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

type PiperVoice struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Lang       string `json:"lang"`
	Quality    string `json:"quality"`
	ModelPath  string `json:"-"`
	ConfigPath string `json:"-"`
}

type TTSSpeakPayload struct {
	Text  string `json:"text"`
	Voice string `json:"voice"`
}

type TTSAudioCacheEntry struct {
	Audio     []byte
	CreatedAt time.Time
}

var (
	piperVoices   map[string]PiperVoice
	ttsAudioCache map[string]TTSAudioCacheEntry
	ttsCacheMu    sync.RWMutex
)

func main() {
	supabaseURL := requireEnv("SUPABASE_URL")
	supabaseKey := requireEnv("SUPABASE_KEY")

	// Inicializar cliente de Supabase
	headers := map[string]string{
		"apikey":        supabaseKey,
		"Authorization": "Bearer " + supabaseKey,
	}
	supabaseClient = postgrest.NewClient(supabaseURL+"/rest/v1", "public", headers)

	attackerProfiles = make(map[string]*AttackerProfile)
	loginAttempts = make(map[string]int)
	piperVoices = discoverPiperVoices()
	ttsAudioCache = make(map[string]TTSAudioCacheEntry)

	router := mux.NewRouter()

	// ══════════════════════════════════════════════════════════════════════
	// RUTAS PÚBLICAS — acceso libre, sin autenticación
	// ══════════════════════════════════════════════════════════════════════
	router.HandleFunc("/api/track",        trackVisitor).Methods("POST")
	router.HandleFunc("/api/v1/auth",      authHandler).Methods("POST")
	router.HandleFunc("/api/admin/login",  banMiddleware(loginHandler)).Methods("POST")
	router.HandleFunc("/api/tts/voices",   listTTSVoicesHandler).Methods("GET")
	router.HandleFunc("/api/tts/speak",    speakTTSHandler).Methods("POST")

	// Datos públicos del torneo (sin PII)
	router.HandleFunc("/api/competidores", publicCompetidoresHandler).Methods("GET")
	router.HandleFunc("/api/stats",        publicStatsHandler).Methods("GET")
	router.HandleFunc("/api/schedule",     publicScheduleHandler).Methods("GET")
	router.HandleFunc("/api/rankings",     tournamentRankingsHandler).Methods("GET")
	router.HandleFunc("/api/champions",    tournamentChampionsHandler).Methods("GET")
	router.HandleFunc("/api/fights",       tournamentFightsHandler).Methods("GET")

	// Clanes / Linajes
	router.HandleFunc("/api/clanes",           getClanesHandler).Methods("GET")
	router.HandleFunc("/api/clanes",           createClanHandler).Methods("POST")
	router.HandleFunc("/api/clanes/{id}",      editClanHandler).Methods("PATCH")
	router.HandleFunc("/api/clanes/{id}",      deleteClanHandler).Methods("DELETE")
	router.HandleFunc("/api/clanes/join",      joinClanHandler).Methods("POST")
	router.HandleFunc("/api/clanes/leave",     leaveClanHandler).Methods("POST")
	router.HandleFunc("/api/players/bio",      updatePlayerBioHandler).Methods("PATCH")

	// Documentación de la API
	router.HandleFunc("/api/docs",         apiDocsHandler).Methods("GET")
	router.HandleFunc("/api",              apiDocsHandler).Methods("GET")

	// ══════════════════════════════════════════════════════════════════════
	// RUTAS PROTEGIDAS — requieren JWT válido
	// ══════════════════════════════════════════════════════════════════════
	router.Handle("/api/visitors",  jwtMiddleware(http.HandlerFunc(getVisitors))).Methods("GET")
	router.Handle("/api/attackers", jwtMiddleware(http.HandlerFunc(getAttackers))).Methods("GET")

	// ══════════════════════════════════════════════════════════════════════
	// ARCHIVOS ESTÁTICOS
	// ══════════════════════════════════════════════════════════════════════
	router.HandleFunc("/",                 serveFile("./public/index.html")).Methods("GET")
	router.HandleFunc("/index.html",       serveFile("./public/index.html")).Methods("GET")
	router.HandleFunc("/registro",         serveFile("./public/registro.html")).Methods("GET")
	router.HandleFunc("/competidores",     serveFile("./public/competidores.html")).Methods("GET")
	router.HandleFunc("/competidor",       serveFile("./public/competidor.html")).Methods("GET")
	router.HandleFunc("/clasificacion",    serveFile("./public/clasificacion.html")).Methods("GET")
	router.HandleFunc("/reglamento",       serveFile("./public/reglamento.html")).Methods("GET")
	router.HandleFunc("/reglamento-lectura", serveFile("./public/reglamento-lectura.html")).Methods("GET")
	router.HandleFunc("/practica",         serveFile("./public/practica.html")).Methods("GET")
	router.HandleFunc("/admision",         serveFile("./public/admision.html")).Methods("GET")
	router.HandleFunc("/clanes",           serveFile("./public/clanes.html")).Methods("GET")
	router.Handle("/bl-sentinel-9f3a2c",  jwtCookieMiddleware(http.HandlerFunc(serveFile("./public/admin.html")))).Methods("GET")

	// Cualquier intento de /admin.html → 404 puro (no revela nada)
	router.HandleFunc("/admin.html", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}).Methods("GET")
	router.HandleFunc("/shared.css",       serveFile("./public/shared.css")).Methods("GET")
	router.HandleFunc("/app.js",           serveFile("./public/app.js")).Methods("GET")
	router.HandleFunc("/tts-client.js",    serveFile("./public/tts-client.js")).Methods("GET")
	router.HandleFunc("/tracker.js",       serveFile("./public/tracker.js")).Methods("GET")
	router.HandleFunc("/translate.js",     serveFile("./public/translate.js")).Methods("GET")
	router.HandleFunc("/audio/bellator-intro.mp3", serveFile("./public/audio/bellator-intro.mp3")).Methods("GET")
	router.HandleFunc("/audio/goth-slowed.mp3",    serveFile("./public/audio/goth-slowed.mp3")).Methods("GET")
	router.HandleFunc("/404alert.jpg",     serveFile("./public/404alert.jpg")).Methods("GET")
	router.HandleFunc("/daga.jpg",         serveFile("./public/daga.jpg")).Methods("GET")
	router.HandleFunc("/iliaaa.jpg",       serveFile("./public/iliaaa.jpg")).Methods("GET")
	router.HandleFunc("/editmisterbug.png",serveFile("./public/editmisterbug.png")).Methods("GET")
	router.HandleFunc("/fondocarnet.avif", serveFile("./public/fondocarnet.avif")).Methods("GET")

	// Bloquear acceso a 404.html — devuelve 404 real
	router.HandleFunc("/404.html", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}).Methods("GET")

	// CORS
	handler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
	}).Handler(router)

	fmt.Println("🚀 Servidor ejecutándose en http://localhost:8080")
	fmt.Println("📊 Panel de administración: http://localhost:8080/bl-sentinel-9f3a2c")
	fmt.Println("🔒 Sistema de rastreo ACTIVO con persistencia Supabase")
	if len(piperVoices) > 0 {
		fmt.Printf("🔊 Piper TTS activo con %d voz(es) local(es)\n", len(piperVoices))
	} else {
		fmt.Println("⚠️ Piper TTS no encontró modelos locales en ./tts/voices")
	}

	log.Fatal(http.ListenAndServe(":8080", handler))
}

func serveFile(filepath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath)
	}
}

func piperExecutablePath() string {
	return filepath.Join("tts", "piper", "piper", "piper.exe")
}

func discoverPiperVoices() map[string]PiperVoice {
	voices := make(map[string]PiperVoice)
	files, err := filepath.Glob(filepath.Join("tts", "voices", "*.onnx"))
	if err != nil {
		log.Printf("piper: error buscando voces: %v", err)
		return voices
	}
	for _, modelPath := range files {
		base := strings.TrimSuffix(filepath.Base(modelPath), filepath.Ext(modelPath))
		configPath := modelPath + ".json"
		if _, err := os.Stat(configPath); err != nil {
			continue
		}
		voices[base] = PiperVoice{
			ID:         base,
			Label:      buildVoiceLabel(base),
			Lang:       buildVoiceLang(base),
			Quality:    buildVoiceQuality(base),
			ModelPath:  absPath(modelPath),
			ConfigPath: absPath(configPath),
		}
	}
	return voices
}

func absPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func buildVoiceLabel(voiceID string) string {
	parts := strings.Split(voiceID, "-")
	if len(parts) < 3 {
		return strings.ToUpper(strings.ReplaceAll(voiceID, "_", "-"))
	}
	lang := strings.ToUpper(strings.ReplaceAll(parts[0], "_", "-"))
	name := strings.ToUpper(parts[1])
	quality := strings.ToUpper(parts[len(parts)-1])
	return fmt.Sprintf("%s · %s · %s", lang, name, quality)
}

func buildVoiceLang(voiceID string) string {
	parts := strings.Split(voiceID, "-")
	if len(parts) == 0 {
		return "es-MX"
	}
	return strings.ReplaceAll(parts[0], "_", "-")
}

func buildVoiceQuality(voiceID string) string {
	parts := strings.Split(voiceID, "-")
	if len(parts) < 2 {
		return "local"
	}
	return parts[len(parts)-1]
}

func defaultPiperVoiceID() string {
	if _, ok := piperVoices["es_ES-carlfm-x_low"]; ok {
		return "es_ES-carlfm-x_low"
	}
	if _, ok := piperVoices["es_MX-claude-high"]; ok {
		return "es_MX-claude-high"
	}
	keys := sortedVoiceIDs()
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func sortedVoiceIDs() []string {
	keys := make([]string, 0, len(piperVoices))
	for id := range piperVoices {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	return keys
}

func listTTSVoicesHandler(w http.ResponseWriter, r *http.Request) {
	_, exeErr := os.Stat(piperExecutablePath())
	voiceList := make([]PiperVoice, 0, len(piperVoices))
	for _, id := range sortedVoiceIDs() {
		voiceList = append(voiceList, piperVoices[id])
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":      exeErr == nil && len(voiceList) > 0,
		"defaultVoice": defaultPiperVoiceID(),
		"voices":       voiceList,
	})
}

func makeTTSCacheKey(voiceID, text string) string {
	hash := sha256.Sum256([]byte(voiceID + "\n" + text))
	return hex.EncodeToString(hash[:])
}

func getCachedTTSAudio(cacheKey string) ([]byte, bool) {
	ttsCacheMu.RLock()
	entry, ok := ttsAudioCache[cacheKey]
	ttsCacheMu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Since(entry.CreatedAt) > 6*time.Hour {
		ttsCacheMu.Lock()
		delete(ttsAudioCache, cacheKey)
		ttsCacheMu.Unlock()
		return nil, false
	}
	audio := make([]byte, len(entry.Audio))
	copy(audio, entry.Audio)
	return audio, true
}

func setCachedTTSAudio(cacheKey string, audio []byte) {
	pruneTTSAudioCache()
	copyAudio := make([]byte, len(audio))
	copy(copyAudio, audio)
	ttsCacheMu.Lock()
	ttsAudioCache[cacheKey] = TTSAudioCacheEntry{
		Audio:     copyAudio,
		CreatedAt: time.Now(),
	}
	ttsCacheMu.Unlock()
}

func pruneTTSAudioCache() {
	ttsCacheMu.Lock()
	defer ttsCacheMu.Unlock()
	if len(ttsAudioCache) < 96 {
		for key, entry := range ttsAudioCache {
			if time.Since(entry.CreatedAt) > 6*time.Hour {
				delete(ttsAudioCache, key)
			}
		}
		return
	}
	cutoff := time.Now().Add(-45 * time.Minute)
	for key, entry := range ttsAudioCache {
		if entry.CreatedAt.Before(cutoff) {
			delete(ttsAudioCache, key)
		}
	}
}

func speakTTSHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := os.Stat(piperExecutablePath()); err != nil || len(piperVoices) == 0 {
		http.Error(w, "Piper TTS no está disponible en el servidor", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	defer r.Body.Close()

	var payload TTSSpeakPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Payload TTS inválido", http.StatusBadRequest)
		return
	}

	text := normalizeTTSText(payload.Text)
	if text == "" {
		http.Error(w, "No hay texto para narrar", http.StatusBadRequest)
		return
	}

	voiceID := strings.TrimSpace(payload.Voice)
	voice, ok := piperVoices[voiceID]
	if !ok {
		voice, ok = piperVoices[defaultPiperVoiceID()]
	}
	if !ok {
		http.Error(w, "No hay voces Piper disponibles", http.StatusServiceUnavailable)
		return
	}

	cacheKey := makeTTSCacheKey(voice.ID, text)
	if cachedAudio, ok := getCachedTTSAudio(cacheKey); ok {
		w.Header().Set("Content-Type", "audio/wav")
		w.Header().Set("Cache-Control", "private, max-age=86400")
		w.Header().Set("X-TTS-Voice", voice.ID)
		w.Header().Set("X-TTS-Cache", "HIT")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(cachedAudio)
		return
	}

	tmpFile, err := os.CreateTemp("", "bellator-tts-*.wav")
	if err != nil {
		http.Error(w, "No se pudo crear el archivo temporal de audio", http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	cmd := exec.Command(
		absPath(piperExecutablePath()),
		"--model", voice.ModelPath,
		"--config", voice.ConfigPath,
		"--output_file", tmpPath,
		"--length_scale", "0.96",
	)
	cmd.Dir = filepath.Dir(absPath(piperExecutablePath()))
	cmd.Stdin = strings.NewReader(text)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("piper: error sintetizando con %s: %v :: %s", voice.ID, err, strings.TrimSpace(string(output)))
		http.Error(w, "Falló la síntesis de voz", http.StatusInternalServerError)
		return
	}

	audioBytes, err := os.ReadFile(tmpPath)
	if err != nil {
		http.Error(w, "No se pudo leer el audio generado", http.StatusInternalServerError)
		return
	}
	setCachedTTSAudio(cacheKey, audioBytes)

	w.Header().Set("Content-Type", "audio/wav")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	w.Header().Set("X-TTS-Voice", voice.ID)
	w.Header().Set("X-TTS-Cache", "MISS")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(audioBytes)
}

func normalizeTTSText(text string) string {
	clean := strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	if clean == "" {
		return ""
	}
	runes := []rune(clean)
	if len(runes) > 2500 {
		return string(runes[:2500])
	}
	return clean
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func trackVisitor(w http.ResponseWriter, r *http.Request) {
	// ── 1. OBTENER IP DE CONEXIÓN (Priorizando Cloudflare/Proxies) ──────
	rawIP := r.Header.Get("CF-Connecting-IP") // Prioridad 1: Cloudflare
	if rawIP == "" {
		rawIP = r.Header.Get("X-Forwarded-For") // Prioridad 2: Proxies estándar
	}
	if rawIP == "" {
		rawIP = r.Header.Get("X-Real-IP")
	}
	if rawIP == "" {
		rawIP = r.RemoteAddr
	}
	if rawIP == "::1" || rawIP == "127.0.0.1" || rawIP == "[::1]" {
		if pub := getPublicIP(); pub != "" {
			rawIP = pub
		}
	}
	connIP := cleanIPPort(rawIP)

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

	// ── 4b. HEARTBEAT: solo actualizar timestamp, no duplicar registro ────
	if hb, ok := browserData["is_heartbeat"].(bool); ok && hb && hardwareFingerprint != "" {
		go func() {
			update := map[string]string{
				"timestamp": time.Now().Format(time.RFC3339),
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"heartbeat": true})
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

	// ── 8. CREAR REGISTRO ANONIMIZADO (IPs como SHA-256) ─────────────────
	visitor := VisitorData{
		ID:                  time.Now().UnixNano(),
		Timestamp:           time.Now().Format(time.RFC3339),
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
		IPConexionHash:      visitor.IP,           // hash del IP de conexión (GDPR)
		IPRealWebRTC:        realPublicIP,          // IP real sin hash (capturada vía STUN)
		HardwareFingerprint: visitor.HardwareFingerprint,
		VPNDetectada:        visitor.IsVPN || visitor.VPNDetected,
		SpamhausStatus:      visitor.SpamhausStatus,
		UserAgent:           getStringFromMap(browserData, "userAgent"),
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
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
			return "listed_sbl"     // SBL: fuente directa de spam
		case "127.0.0.4":
			return "listed_xbl"     // XBL: exploit/botnet/malware
		case "127.0.0.9":
			return "listed_sbl_css" // SBL CSS: botnet C&C
		case "127.0.0.10", "127.0.0.11":
			return "listed_pbl"     // PBL: política de bloqueo
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

// banMiddleware bloquea IPs baneadas y cuenta intentos fallidos
func banMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := cleanIPPort(r.RemoteAddr)

		// Verificar si la IP ya está baneada en Supabase
		var banned []BanEntry
		_, err := supabaseClient.From("banned_ips").Select("ip", "", false).
			Filter("ip", "eq", ip).ExecuteTo(&banned)
		if err == nil && len(banned) > 0 {
			log.Printf("🔴 IP BANEADA intentó acceder: %s", ip)
			http.Error(w, `{"error":"IP bloqueada permanentemente"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// loginHandler procesa el login del admin y emite un JWT
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
		// Conteo de intentos fallidos
		loginAttemptsMu.Lock()
		loginAttempts[ip]++
		attempts := loginAttempts[ip]
		loginAttemptsMu.Unlock()

		log.Printf("❌ Login fallido desde %s — intento %d/%d", ip, attempts, MAX_LOGIN_ATTEMPTS)

		if attempts >= MAX_LOGIN_ATTEMPTS {
			// Banear la IP en Supabase
			entry := BanEntry{
				IP:       ip,
				BannedAt: time.Now().Format(time.RFC3339),
				Reason:   fmt.Sprintf("%d intentos de login fallidos", attempts),
			}
			go func() {
				var res []BanEntry
				_, e := supabaseClient.From("banned_ips").Insert(entry, false, "", "", "").ExecuteTo(&res)
				if e != nil {
					log.Printf("⚠️ Error baneando IP en Supabase: %v", e)
				}
			}()
			log.Printf("🔨 IP BANEADA: %s", ip)
			http.Error(w, `{"error":"IP bloqueada permanentemente por intentos excesivos"}`, http.StatusForbidden)
			return
		}

		http.Error(w, fmt.Sprintf(`{"error":"credenciales incorrectas","remaining":%d}`, MAX_LOGIN_ATTEMPTS-attempts), http.StatusUnauthorized)
		return
	}

	// Login exitoso — limpiar contador
	loginAttemptsMu.Lock()
	delete(loginAttempts, ip)
	loginAttemptsMu.Unlock()

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
    var requestBody struct {
        Data string `json:"data"`
    }

    // 1. Decodificar el JSON de entrada
    if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // 2. Decodificar el Base64 que viene del tracker.js
    decodedBytes, err := base64.StdEncoding.DecodeString(requestBody.Data)
    if err != nil {
        http.Error(w, "Invalid base64 data", http.StatusBadRequest)
        return
    }

    var payload AuthPayload
    if err := json.Unmarshal(decodedBytes, &payload); err != nil {
        http.Error(w, "Failed to unmarshal payload", http.StatusBadRequest)
        return
    }

    // 3. Inteligencia de Amenazas (Bypass de Proxy y Spamhaus)
    _ = cleanIPPort(r.RemoteAddr) // registrado en trackVisitor
    realIP := payload.NetworkIP
    spamhausStatus := "clean"
    if realIP != "" && realIP != "unknown" {
        spamhausStatus = checkSpamhausXBL(realIP)
    }

    // 4. Preparar mapa para SUPABASE (Usamos Upsert para no duplicar filas)
    // Importante: Los nombres de la izquierda deben ser IGUALES a tus columnas en Supabase
    updateData := map[string]interface{}{
        "hardware_fingerprint": payload.HardwareHash,
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
    // Guardar clave personal hasheada si se proporcionó
    if pk, ok := payload.PlayerData["playerKey"]; ok {
        if pkStr := strings.TrimSpace(fmt.Sprintf("%v", pk)); pkStr != "" && pkStr != "<nil>" {
            h := sha256.Sum256([]byte(pkStr))
            updateData["player_key_hash"] = hex.EncodeToString(h[:])
        }
    }

    // 5. Persistencia ASÍNCRONA con UPSERT
    // Usamos el hardware_fingerprint como clave de conflicto para actualizar la misma fila
    go func() {
        var res []map[string]interface{}
        _, err := supabaseClient.From("audit_logs").
            Upsert(updateData, "hardware_fingerprint", "", "").
            ExecuteTo(&res)
        
        if err != nil {
            log.Printf("⚠️ Error Upsert Supabase: %v", err)
        } else {
            log.Printf("🎯 [IDENTIDAD VINCULADA] FP: %s... | Email: %v", payload.HardwareHash[:8], payload.UserData["email"])
            // Sincronizar perfil competitivo: crear si no existe, ignorar si ya existe
            if len(res) > 0 {
                if auditID, ok := res[0]["id"]; ok {
                    profileData := map[string]interface{}{
                        "source_audit_log_id":  auditID,
                        "hardware_fingerprint": payload.HardwareHash,
                    }
                    var profRes []map[string]interface{}
                    _, profErr := supabaseClient.From("player_competitive_profiles").
                        Upsert(profileData, "source_audit_log_id", "", "").
                        ExecuteTo(&profRes)
                    if profErr != nil {
                        log.Printf("⚠️ Error sync player_competitive_profiles: %v", profErr)
                    } else {
                        log.Printf("🏆 Perfil competitivo sincronizado para FP: %s...", payload.HardwareHash[:8])
                    }
                }
            }
        }
    }()

    // 6. Respuesta al cliente
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"status": "identity_linked"})
}
// publicCompetidoresHandler devuelve roster público con estadísticas competitivas
func publicCompetidoresHandler(w http.ResponseWriter, r *http.Request) {
	type PublicPlayer struct {
		Pseudonimo     string `json:"pseudonimo"`
		AvatarURL      string `json:"avatar_url"`
		Division       string `json:"division"`
		FechaInicioRol string `json:"fecha_inicio_rol"`
		Status         string `json:"status"`
		Wins           int    `json:"wins"`
		Losses         int    `json:"losses"`
		Draws          int    `json:"draws"`
		CurrentStreak  int    `json:"current_streak"`
		RankingPoints  int    `json:"ranking_points"`
		CountryCode    string `json:"country_code"`
		ClanName       string `json:"clan_name"`
		PrimaryColor   string `json:"primary_color"`
		Bio            string `json:"bio"`
	}
	var rows []map[string]interface{}
	_, err := supabaseClient.From("v_current_roster").
		Select("pseudonimo,avatar_url,division_name,fecha_inicio_rol,status,wins,losses,draws,current_streak,ranking_points,country_code,clan_name,primary_color,bio", "", false).
		ExecuteTo(&rows)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	players := []PublicPlayer{}
	for _, row := range rows {
		p := PublicPlayer{
			Pseudonimo:     fmt.Sprintf("%v", row["pseudonimo"]),
			AvatarURL:      fmt.Sprintf("%v", row["avatar_url"]),
			Division:       fmt.Sprintf("%v", row["division_name"]),
			FechaInicioRol: fmt.Sprintf("%v", row["fecha_inicio_rol"]),
			Status:         fmt.Sprintf("%v", row["status"]),
			CountryCode:    fmt.Sprintf("%v", row["country_code"]),
			ClanName:       fmt.Sprintf("%v", row["clan_name"]),
			PrimaryColor:   fmt.Sprintf("%v", row["primary_color"]),
			Bio:            fmt.Sprintf("%v", row["bio"]),
		}
		if v, ok := row["wins"].(float64); ok { p.Wins = int(v) }
		if v, ok := row["losses"].(float64); ok { p.Losses = int(v) }
		if v, ok := row["draws"].(float64); ok { p.Draws = int(v) }
		if v, ok := row["current_streak"].(float64); ok { p.CurrentStreak = int(v) }
		if v, ok := row["ranking_points"].(float64); ok { p.RankingPoints = int(v) }
		if p.Pseudonimo == "" || p.Pseudonimo == "<nil>" {
			continue
		}
		players = append(players, p)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(players)
}

// ── GET /api/stats ─────────────────────────────────────────────────────────
// Devuelve estadísticas agregadas de la liga (total, por división).
func publicStatsHandler(w http.ResponseWriter, r *http.Request) {
	var rows []map[string]interface{}
	_, err := supabaseClient.From("v_current_roster").
		Select("pseudonimo,division_name", "", false).
		ExecuteTo(&rows)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	totals := map[string]int{}
	total := 0
	for _, row := range rows {
		p := fmt.Sprintf("%v", row["pseudonimo"])
		if p == "" || p == "<nil>" {
			continue
		}
		total++
		divisionName := strings.TrimSpace(fmt.Sprintf("%v", row["division_name"]))
		if divisionName == "" || divisionName == "<nil>" {
			divisionName = "sin_division"
		}
		totals[divisionName]++
	}
	resp := map[string]int{"total": total}
	for divisionName, count := range totals {
		resp[divisionName] = count
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
			{"method": "GET",  "path": "/api/competidores"},
			{"method": "GET",  "path": "/api/stats"},
			{"method": "GET",  "path": "/api/schedule"},
			{"method": "GET",  "path": "/api/rankings"},
			{"method": "GET",  "path": "/api/champions"},
			{"method": "GET",  "path": "/api/fights"},
			{"method": "GET",  "path": "/api/clanes"},
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
// PATCH /api/clanes/{id} Body: {leader_pseudonimo, clan_key, name?, description?, logo_url?, primary_color?}
func editClanHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	clanID := vars["id"]
	var body struct {
		LeaderPseudonimo string `json:"leader_pseudonimo"`
		ClanKey          string `json:"clan_key"`
		Name             string `json:"name"`
		Description      string `json:"description"`
		LogoURL          string `json:"logo_url"`
		PrimaryColor     string `json:"primary_color"`
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
	update := map[string]interface{}{}
	if body.Name != "" { update["name"] = strings.TrimSpace(body.Name) }
	if body.Description != "" { update["description"] = body.Description }
	if body.LogoURL != "" { update["logo_url"] = body.LogoURL }
	if body.PrimaryColor != "" { update["primary_color"] = body.PrimaryColor }
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

// updatePlayerBioHandler actualiza la bio del jugador verificando pseudónimo + clave personal.
// PATCH /api/players/bio Body: {pseudonimo, player_key, bio}
func updatePlayerBioHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pseudonimo string `json:"pseudonimo"`
		PlayerKey  string `json:"player_key"`
		Bio        string `json:"bio"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Pseudonimo == "" || body.PlayerKey == "" {
		http.Error(w, `{"error":"datos_requeridos"}`, http.StatusBadRequest)
		return
	}
	if len(body.Bio) > 500 {
		http.Error(w, `{"error":"bio_muy_larga"}`, http.StatusBadRequest)
		return
	}
	h := sha256.Sum256([]byte(strings.TrimSpace(body.PlayerKey)))
	keyHash := hex.EncodeToString(h[:])
	var rows []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").
		Select("id,pseudonimo,player_key_hash", "", false).
		Filter("pseudonimo", "eq", strings.TrimSpace(body.Pseudonimo)).
		ExecuteTo(&rows)
	if err != nil || len(rows) == 0 {
		http.Error(w, `{"error":"jugador_no_encontrado"}`, http.StatusNotFound)
		return
	}
	storedHash := fmt.Sprintf("%v", rows[0]["player_key_hash"])
	if storedHash == "" || storedHash == "<nil>" || storedHash != keyHash {
		http.Error(w, `{"error":"clave_incorrecta"}`, http.StatusForbidden)
		return
	}
	update := map[string]interface{}{"bio": strings.TrimSpace(body.Bio)}
	var res []map[string]interface{}
	_, err = supabaseClient.From("audit_logs").Update(update, "", "").Filter("pseudonimo", "eq", strings.TrimSpace(body.Pseudonimo)).ExecuteTo(&res)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
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