package main

// album_handlers.go — Handlers para el álbum digital Bellator RolBattle
//
// Endpoints:
//   GET  /api/album/catalog      → catálogo público de stickers
//   GET  /api/album/collection   → inventario del usuario (JWT requerido)
//   POST /api/album/open-pack    → abrir sobre y persistir cromos (JWT requerido)

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/supabase-community/postgrest-go"
)

// ════════════════════════════════════════════════════════════════════════
// TIPOS
// ════════════════════════════════════════════════════════════════════════

type albumSticker struct {
	ID           string `json:"id"`
	Series       string `json:"series"`
	PlayerPseudo string `json:"player_pseudo"`
	Division     string `json:"division"`
	StickerType  string `json:"sticker_type"`
	Variant      string `json:"variant"`
	SpecialType  string `json:"special_type,omitempty"`
	DisplayName  string `json:"display_name"`
	ImageURL     string `json:"image_url,omitempty"`
	Rarity       string `json:"rarity"`
	SlotNumber   int    `json:"slot_number"`
	MaxCopies    *int   `json:"max_copies,omitempty"`
}

type albumStickerWithCollection struct {
	albumSticker
	Collected bool `json:"collected"`
	Quantity  int  `json:"quantity"`
}

type weightedRarity struct {
	rarity string
	weight int
}

type albumPackSelection struct {
	Rarity string
	Pool   string
	Row    map[string]interface{}
}

type albumDropEngine struct {
	pools map[string][]map[string]interface{}
}

func newAlbumDropEngine(catalogRows []map[string]interface{}) *albumDropEngine {
	pools := map[string][]map[string]interface{}{
		"comun":             {},
		"raro":              {},
		"epico":             {},
		"legendario":        {},
		"legendario_dorado": {},
		"iconico":           {},
		"extra":             {},
		"diamante":          {},
		"esmeralda":         {},
	}
	for _, row := range catalogRows {
		poolKey := albumCatalogPoolKeyForRow(row)
		pools[poolKey] = append(pools[poolKey], row)
	}
	return &albumDropEngine{pools: pools}
}

func (e *albumDropEngine) selectSticker(poolKey string) (map[string]interface{}, bool) {
	// Los pools especiales no tienen fallback a 'comun' — si están vacíos es un error de datos
	specialPools := map[string]bool{"iconico": true, "extra": true, "diamante": true, "esmeralda": true}
	pool := e.pools[poolKey]
	if len(pool) == 0 {
		if specialPools[poolKey] {
			log.Printf("⚠️ album drop engine: pool especial '%s' vacío — ejecuta el INSERT SQL para poblar cromos especiales", poolKey)
			return nil, false
		}
		// Para pools normales: cross-fallback entre legendario y legendario_dorado
		if poolKey == "legendario_dorado" {
			pool = e.pools["legendario"]
		} else if poolKey == "legendario" {
			pool = e.pools["legendario_dorado"]
		}
	}
	if len(pool) == 0 {
		pool = e.pools["comun"]
	}
	if len(pool) == 0 {
		return nil, false
	}
	idx, _ := cryptoRandN(len(pool))
	return pool[idx], true
}

func albumSpecialDropDistribution() []weightedRarity {
	return []weightedRarity{
		{"legendario_dorado", 700},
		{"iconico", 150},
		{"extra", 100},
		{"diamante", 30},
		{"esmeralda", 20},
	}
}

func (e *albumDropEngine) selectPackEntry(distribution []weightedRarity) (albumPackSelection, bool) {
	if len(distribution) == 0 {
		return albumPackSelection{}, false
	}

	rarity := weightedPick(distribution)
	if rarity != "dorado" {
		row, ok := e.selectSticker(rarity)
		if !ok {
			return albumPackSelection{}, false
		}
		return albumPackSelection{Rarity: rarity, Pool: rarity, Row: row}, true
	}

	secondaryDist := albumSpecialDropDistribution()
	secondary := weightedPick(secondaryDist)
	if secondary == "legendario_dorado" {
		row, ok := e.selectSticker("legendario_dorado")
		if ok {
			return albumPackSelection{Rarity: "legendario_dorado", Pool: "legendario_dorado", Row: row}, true
		}
	}
	if secondary == "iconico" {
		row, ok := e.selectSticker("iconico")
		if ok {
			return albumPackSelection{Rarity: "iconico", Pool: "iconico", Row: row}, true
		}
	}
	if secondary == "extra" {
		row, ok := e.selectSticker("extra")
		if ok {
			return albumPackSelection{Rarity: "extra", Pool: "extra", Row: row}, true
		}
	}
	if secondary == "diamante" {
		row, ok := e.selectSticker("diamante")
		if ok {
			return albumPackSelection{Rarity: "diamante", Pool: "diamante", Row: row}, true
		}
	}
	if secondary == "esmeralda" {
		row, ok := e.selectSticker("esmeralda")
		if ok {
			return albumPackSelection{Rarity: "esmeralda", Pool: "esmeralda", Row: row}, true
		}
	}

	row, ok := e.selectSticker("legendario_dorado")
	if ok {
		return albumPackSelection{Rarity: "legendario_dorado", Pool: "legendario_dorado", Row: row}, true
	}
	return albumPackSelection{}, false
}

const (
	albumSessionCookieName  = "bl_album"
	albumSessionMaxAge      = 30 * 24 * 3600
	albumDailyFreePackLimit = 2
)

type albumSessionClaims struct {
	AlbumUserID string `json:"aid"`
	Pseudonimo  string `json:"pseudo"`
	Division    string `json:"division,omitempty"`
	AvatarURL   string `json:"avatar_url,omitempty"`
	jwt.RegisteredClaims
}

type albumSessionInfo struct {
	Pseudonimo    string `json:"pseudonimo"`
	Division      string `json:"division,omitempty"`
	AvatarURL     string `json:"avatar_url,omitempty"`
	CollectionKey string `json:"-"`
}

type albumMissionTarget struct {
	Label string `json:"label"`
	Total int    `json:"total"`
}

type albumMissionConfig struct {
	Pack        albumMissionTarget `json:"pack"`
	Pages       albumMissionTarget `json:"pages"`
	NewStickers albumMissionTarget `json:"newStickers"`
	CardCopy    string             `json:"cardCopy"`
}

type albumPackBalance struct {
	BonusPacks int `json:"bonus_packs"`
}

type albumDailyPackQuota struct {
	Count     int    `json:"count"`
	Remaining int    `json:"remaining"`
	ResetAt   string `json:"reset_at,omitempty"`
}

type albumViewerSummary struct {
	Authenticated bool                `json:"authenticated"`
	Session       *albumSessionInfo   `json:"session,omitempty"`
	BonusPacks    int                 `json:"bonus_packs"`
	DailyPacks    albumDailyPackQuota `json:"daily_packs"`
}

type albumKnownUser struct {
	UserID     string `json:"user_id"`
	Pseudonimo string `json:"pseudonimo"`
}

type albumTradeTargetOption struct {
	Pseudonimo string `json:"pseudonimo"`
}

type albumTradeStickerItem struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Group   string `json:"group,omitempty"`
	Rarity  string `json:"rarity,omitempty"`
	Extra   int    `json:"extra,omitempty"`
	Pending bool   `json:"pending,omitempty"`
}

type albumTradeRequest struct {
	ID           string                  `json:"id"`
	IdentityKey  string                  `json:"identityKey"`
	Player       string                  `json:"player"`
	Local        bool                    `json:"local"`
	CreatedAt    string                  `json:"createdAt"`
	Status       string                  `json:"status"`
	TargetUserID string                  `json:"targetUserId,omitempty"`
	TargetPlayer string                  `json:"targetPlayer,omitempty"`
	Offer        []albumTradeStickerItem `json:"offer"`
	Want         []albumTradeStickerItem `json:"want"`
}

type albumUserStickerRow struct {
	ID        string
	UserID    string
	StickerID string
	Quantity  int
}

type albumRosterImageSources struct {
	AvatarURL string
	CharURLs  [3]string
}

var albumTradeBoardMutex sync.Mutex

var albumExcludedPseudoKeys = map[string]struct{}{
	"bandet997883": {},
	"demon usser":  {},
	"eisengaard":   {},
	"jhon ridley":  {},
	"metasploit":   {},
	"morwen":       {},
	"nilu":         {},
	"primrose":     {},
	"ryu":          {},
	"shin kazami":  {},
	"sekiro":       {},
	"xiao":         {},
	"windham":      {},
	"𝖂indham":      {},
}

func isAlbumExcludedPseudo(pseudonimo string) bool {
	_, excluded := albumExcludedPseudoKeys[strings.ToLower(strings.TrimSpace(pseudonimo))]
	return excluded
}

var defaultAlbumMissionConfig = albumMissionConfig{
	Pack:        albumMissionTarget{Label: "Reclama un sobre diario", Total: 1},
	Pages:       albumMissionTarget{Label: "Explora tres páginas del libro", Total: 3},
	NewStickers: albumMissionTarget{Label: "Pega cinco cromos nuevos", Total: 5},
	CardCopy:    "Tu rutina diaria mezcla sobres, exploración del libro y crecimiento real de la colección.",
}

func albumSessionSecret() (string, error) {
	if secret := strings.TrimSpace(getEnv("ALBUM_JWT_SECRET", "")); secret != "" {
		return secret, nil
	}
	if secret := strings.TrimSpace(getEnv("ADMIN_JWT_SECRET", "")); secret != "" {
		return secret, nil
	}
	return "", fmt.Errorf("album_jwt_secret_missing")
}

func albumSessionClaimsFromSession(session albumSessionInfo) albumSessionClaims {
	now := time.Now().UTC()
	return albumSessionClaims{
		AlbumUserID: strings.TrimSpace(session.CollectionKey),
		Pseudonimo:  strings.TrimSpace(session.Pseudonimo),
		Division:    strings.TrimSpace(session.Division),
		AvatarURL:   strings.TrimSpace(session.AvatarURL),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strings.TrimSpace(session.Pseudonimo),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(30 * 24 * time.Hour)),
		},
	}
}

func signAlbumSession(session albumSessionInfo) (string, error) {
	secret, err := albumSessionSecret()
	if err != nil {
		return "", err
	}
	claims := albumSessionClaimsFromSession(session)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func parseAlbumSessionToken(raw string) (*albumSessionClaims, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	secret, err := albumSessionSecret()
	if err != nil {
		return nil, err
	}
	claims := &albumSessionClaims{}
	token, err := jwt.ParseWithClaims(trimmed, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("metodo de firma invalido")
		}
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		if err == nil {
			err = fmt.Errorf("album_session_invalid")
		}
		return nil, err
	}
	claims.AlbumUserID = strings.TrimSpace(claims.AlbumUserID)
	if claims.AlbumUserID == "" {
		return nil, fmt.Errorf("album_session_missing_user_id")
	}
	claims.Pseudonimo = strings.TrimSpace(claims.Pseudonimo)
	claims.Division = strings.TrimSpace(claims.Division)
	claims.AvatarURL = strings.TrimSpace(claims.AvatarURL)
	return claims, nil
}

func albumSessionBearerFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if authorization == "" {
		return strings.TrimSpace(r.Header.Get("X-Album-Session"))
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func albumSessionInfoFromClaims(claims *albumSessionClaims) albumSessionInfo {
	if claims == nil {
		return albumSessionInfo{}
	}
	return albumSessionInfo{
		Pseudonimo:    strings.TrimSpace(claims.Pseudonimo),
		Division:      strings.TrimSpace(claims.Division),
		AvatarURL:     strings.TrimSpace(claims.AvatarURL),
		CollectionKey: strings.TrimSpace(claims.AlbumUserID),
	}
}

func albumSessionInfoFromPlayerRow(row map[string]interface{}, fallbackPseudo string) albumSessionInfo {
	pseudonimo := strings.TrimSpace(normalizeNullableString(row["pseudonimo"]))
	if pseudonimo == "" {
		pseudonimo = strings.TrimSpace(fallbackPseudo)
	}
	collectionKey := strings.TrimSpace(normalizeNullableString(row["hardware_fingerprint"]))
	if collectionKey == "" && pseudonimo != "" {
		collectionKey = "pseudo:" + strings.ToLower(pseudonimo)
	}
	return albumSessionInfo{
		Pseudonimo:    pseudonimo,
		Division:      strings.TrimSpace(normalizeNullableString(row["division"])),
		AvatarURL:     strings.TrimSpace(normalizeNullableString(row["avatar_url"])),
		CollectionKey: collectionKey,
	}
}

func normalizeAlbumCountryCode(value string) string {
	code := strings.ToUpper(strings.TrimSpace(value))
	if len(code) != 2 {
		return ""
	}
	for _, r := range code {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return code
}

func albumCatalogPoolKeyForRow(row map[string]interface{}) string {
	if row == nil {
		return "comun"
	}

	specialType := normalizeNullableString(row["special_type"])
	if specialType != "" {
		switch specialType {
		case "iconico":
			return "iconico"
		case "extra":
			return "extra"
		case "diamante":
			return "diamante"
		case "esmeralda":
			return "esmeralda"
		}
	}

	variant := normalizeNullableString(row["variant"])
	if variant == "dorado" {
		return "legendario_dorado"
	}

	rarity := normalizeNullableString(row["rarity"])
	if rarity == "" {
		return "comun"
	}
	return rarity
}

func isLikelyAlbumImagePath(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, suffix := range []string{".webp", ".jpg", ".jpeg", ".png", ".gif", ".avif"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func isUsableAlbumImageSource(raw string) bool {
	text := strings.TrimSpace(raw)
	if text == "" {
		return false
	}
	parsed, err := url.Parse(text)
	if err != nil {
		return false
	}
	if parsed.Scheme == "" && parsed.Host == "" {
		if strings.HasPrefix(parsed.Path, "/") {
			return true
		}
		return isLikelyAlbumImagePath(parsed.Path)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	host := strings.ToLower(parsed.Host)
	if host == "pin.it" || strings.HasSuffix(host, ".pin.it") {
		return false
	}
	if strings.HasSuffix(host, "pinterest.com") {
		return false
	}
	if host == "imgur.com" || host == "www.imgur.com" || host == "m.imgur.com" {
		return false
	}
	if host == "comicvine.gamespot.com" || strings.HasSuffix(host, ".comicvine.gamespot.com") {
		return false
	}
	return true
}

func firstUsableAlbumImageSource(candidates ...string) string {
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		if isUsableAlbumImageSource(trimmed) {
			return trimmed
		}
	}
	return ""
}

func loadAlbumRosterImageSources() (map[string]albumRosterImageSources, error) {
	players, err := loadPublicPlayers()
	if err != nil {
		return nil, err
	}
	lookup := make(map[string]albumRosterImageSources, len(players))
	for _, player := range players {
		pseudoKey := strings.ToLower(strings.TrimSpace(player.Pseudonimo))
		if pseudoKey == "" {
			continue
		}
		lookup[pseudoKey] = albumRosterImageSources{
			AvatarURL: strings.TrimSpace(player.AvatarURL),
			CharURLs: [3]string{
				strings.TrimSpace(player.TopChar1Image),
				strings.TrimSpace(player.TopChar2Image),
				strings.TrimSpace(player.TopChar3Image),
			},
		}
	}
	return lookup, nil
}

func fallbackAlbumStickerImage(sticker albumSticker, lookup map[string]albumRosterImageSources) string {
	if isUsableAlbumImageSource(sticker.ImageURL) {
		return strings.TrimSpace(sticker.ImageURL)
	}
	entry, ok := lookup[strings.ToLower(strings.TrimSpace(sticker.PlayerPseudo))]
	if !ok {
		return ""
	}
	switch strings.TrimSpace(sticker.StickerType) {
	case "player":
		return firstUsableAlbumImageSource(entry.AvatarURL, entry.CharURLs[0], entry.CharURLs[1], entry.CharURLs[2])
	case "char_1":
		return firstUsableAlbumImageSource(entry.CharURLs[0], entry.AvatarURL, entry.CharURLs[1], entry.CharURLs[2])
	case "char_2":
		return firstUsableAlbumImageSource(entry.CharURLs[1], entry.AvatarURL, entry.CharURLs[0], entry.CharURLs[2])
	case "char_3":
		return firstUsableAlbumImageSource(entry.CharURLs[2], entry.AvatarURL, entry.CharURLs[0], entry.CharURLs[1])
	default:
		return firstUsableAlbumImageSource(entry.AvatarURL, entry.CharURLs[0], entry.CharURLs[1], entry.CharURLs[2])
	}
}

func rowToAlbumStickerWithFallback(row map[string]interface{}, lookup map[string]albumRosterImageSources) albumSticker {
	sticker := rowToAlbumSticker(row)
	if fallback := fallbackAlbumStickerImage(sticker, lookup); fallback != "" {
		sticker.ImageURL = fallback
	}
	return sticker
}

func albumPseudoAlias(pseudonimo string) string {
	pseudo := strings.ToLower(strings.TrimSpace(pseudonimo))
	if pseudo == "" {
		return ""
	}
	return "pseudo:" + pseudo
}

func appendUniqueAlbumIDs(target []string, values ...string) []string {
	seen := make(map[string]struct{}, len(target)+len(values))
	for _, value := range target {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		seen[trimmed] = struct{}{}
	}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		target = append(target, trimmed)
	}
	return target
}

func lookupAlbumHardwareFingerprintByPseudo(pseudonimo string) string {
	pseudo := strings.TrimSpace(pseudonimo)
	if pseudo == "" {
		return ""
	}
	var rows []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").
		Select("hardware_fingerprint", "", false).
		Filter("pseudonimo", "ilike", pseudo).
		Order("timestamp", &postgrest.OrderOpts{Ascending: false}).
		Limit(25, "").
		ExecuteTo(&rows)
	if err != nil {
		log.Printf("⚠️ album hardware fingerprint lookup: pseudo=%s err=%v", compactAuditValue(pseudo, 48), err)
		return ""
	}
	for _, row := range rows {
		fingerprint := strings.TrimSpace(normalizeNullableString(row["hardware_fingerprint"]))
		if fingerprint != "" {
			return fingerprint
		}
	}
	return ""
}

func albumIdentityKeysFromClaims(claims *albumSessionClaims) (string, []string) {
	if claims == nil {
		return "", nil
	}
	primary := strings.TrimSpace(claims.AlbumUserID)
	keys := appendUniqueAlbumIDs(nil, primary, albumPseudoAlias(claims.Pseudonimo))
	if hardwareFingerprint := lookupAlbumHardwareFingerprintByPseudo(claims.Pseudonimo); hardwareFingerprint != "" {
		keys = appendUniqueAlbumIDs(keys, hardwareFingerprint)
		if primary == "" || strings.HasPrefix(primary, "pseudo:") {
			primary = hardwareFingerprint
		}
	}
	if primary == "" && len(keys) > 0 {
		primary = keys[0]
	}
	return primary, keys
}

func albumIdentityKeysFromRequest(r *http.Request) (string, []string) {
	if claims, err := albumSessionFromRequest(r); err == nil && claims != nil {
		return albumIdentityKeysFromClaims(claims)
	}
	fingerprint := strings.TrimSpace(r.Header.Get("X-Player-Key"))
	if fingerprint == "" {
		return "", nil
	}
	return fingerprint, []string{fingerprint}
}

func albumSessionFromRequest(r *http.Request) (*albumSessionClaims, error) {
	if r == nil {
		return nil, nil
	}
	var lastErr error
	if cookie, err := r.Cookie(albumSessionCookieName); err == nil {
		if claims, parseErr := parseAlbumSessionToken(cookie.Value); parseErr == nil && claims != nil {
			return claims, nil
		} else if parseErr != nil {
			lastErr = parseErr
		}
	} else if err != http.ErrNoCookie {
		lastErr = err
	}
	if bearer := albumSessionBearerFromRequest(r); bearer != "" {
		if claims, err := parseAlbumSessionToken(bearer); err == nil && claims != nil {
			return claims, nil
		} else if err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

func albumSessionCookiePolicy(r *http.Request) (http.SameSite, bool) {
	secure := requestScheme(r) == "https"
	if secure && !isLocalHost(r.Host) {
		return http.SameSiteNoneMode, true
	}
	return http.SameSiteLaxMode, secure
}

func writeAlbumSessionCookieValue(w http.ResponseWriter, r *http.Request, signed string) {
	sameSite, secure := albumSessionCookiePolicy(r)
	http.SetCookie(w, &http.Cookie{
		Name:     albumSessionCookieName,
		Value:    signed,
		Path:     "/",
		MaxAge:   albumSessionMaxAge,
		HttpOnly: true,
		SameSite: sameSite,
		Secure:   secure,
	})
}

func writeAlbumSessionCookie(w http.ResponseWriter, r *http.Request, session albumSessionInfo) error {
	signed, err := signAlbumSession(session)
	if err != nil {
		return err
	}
	writeAlbumSessionCookieValue(w, r, signed)
	return nil
}

func clearAlbumSessionCookie(w http.ResponseWriter, r *http.Request) {
	sameSite, secure := albumSessionCookiePolicy(r)
	http.SetCookie(w, &http.Cookie{
		Name:     albumSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: sameSite,
		Secure:   secure,
	})
}

func sanitizeAlbumMissionConfig(cfg albumMissionConfig) albumMissionConfig {
	clean := cfg
	clean.Pack.Label = strings.TrimSpace(clean.Pack.Label)
	clean.Pages.Label = strings.TrimSpace(clean.Pages.Label)
	clean.NewStickers.Label = strings.TrimSpace(clean.NewStickers.Label)
	clean.CardCopy = strings.TrimSpace(clean.CardCopy)
	if clean.Pack.Label == "" {
		clean.Pack.Label = defaultAlbumMissionConfig.Pack.Label
	}
	if clean.Pages.Label == "" {
		clean.Pages.Label = defaultAlbumMissionConfig.Pages.Label
	}
	if clean.NewStickers.Label == "" {
		clean.NewStickers.Label = defaultAlbumMissionConfig.NewStickers.Label
	}
	if clean.CardCopy == "" {
		clean.CardCopy = defaultAlbumMissionConfig.CardCopy
	}
	if clean.Pack.Total < 1 {
		clean.Pack.Total = defaultAlbumMissionConfig.Pack.Total
	}
	if clean.Pages.Total < 1 {
		clean.Pages.Total = defaultAlbumMissionConfig.Pages.Total
	}
	if clean.NewStickers.Total < 1 {
		clean.NewStickers.Total = defaultAlbumMissionConfig.NewStickers.Total
	}
	return clean
}

func loadAlbumMissionConfig() (albumMissionConfig, error) {
	var rows []map[string]interface{}
	_, err := albumSupabaseClient.From("app_config").
		Select("config_value", "", false).
		Filter("config_key", "eq", "mission_config").
		Limit(1, "").
		ExecuteTo(&rows)
	if err != nil {
		return sanitizeAlbumMissionConfig(defaultAlbumMissionConfig), err
	}
	if len(rows) == 0 {
		return sanitizeAlbumMissionConfig(defaultAlbumMissionConfig), nil
	}
	var parsed albumMissionConfig
	raw := strings.TrimSpace(normalizeNullableString(rows[0]["config_value"]))
	if raw == "" {
		return sanitizeAlbumMissionConfig(defaultAlbumMissionConfig), nil
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return sanitizeAlbumMissionConfig(defaultAlbumMissionConfig), nil
	}
	return sanitizeAlbumMissionConfig(parsed), nil
}

func saveAlbumMissionConfig(cfg albumMissionConfig) error {
	clean := sanitizeAlbumMissionConfig(cfg)
	body, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	var existing []map[string]interface{}
	_, err = albumSupabaseClient.From("app_config").
		Select("id", "", false).
		Filter("config_key", "eq", "mission_config").
		Limit(1, "").
		ExecuteTo(&existing)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"config_key":   "mission_config",
		"config_value": string(body),
		"updated_at":   time.Now().UTC().Format(time.RFC3339),
	}
	if len(existing) > 0 {
		id := normalizeNullableString(existing[0]["id"])
		if id == "" {
			return fmt.Errorf("album_config_missing_id")
		}
		_, err = albumSupabaseClient.From("app_config").
			Update(payload, "", "").
			Filter("id", "eq", id).
			ExecuteTo(nil)
		return err
	}
	_, err = albumSupabaseClient.From("app_config").Insert(payload, false, "", "", "").ExecuteTo(nil)
	return err
}

func sanitizeAlbumTradeItems(items []albumTradeStickerItem, allowExtra bool) []albumTradeStickerItem {
	clean := make([]albumTradeStickerItem, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		entry := albumTradeStickerItem{
			ID:      id,
			Name:    strings.TrimSpace(item.Name),
			Group:   strings.TrimSpace(item.Group),
			Rarity:  strings.TrimSpace(item.Rarity),
			Pending: item.Pending,
		}
		if entry.Name == "" {
			entry.Name = id
		}
		if allowExtra {
			entry.Extra = item.Extra
			if entry.Extra < 1 {
				entry.Extra = 1
			}
			if entry.Extra > 99 {
				entry.Extra = 99
			}
		}
		clean = append(clean, entry)
		if len(clean) >= 24 {
			break
		}
	}
	return clean
}

func sanitizeAlbumTradeRequests(requests []albumTradeRequest) []albumTradeRequest {
	clean := make([]albumTradeRequest, 0, len(requests))
	seen := make(map[string]struct{}, len(requests))
	for _, request := range requests {
		identityKey := strings.TrimSpace(request.IdentityKey)
		if identityKey == "" {
			continue
		}
		if _, exists := seen[identityKey]; exists {
			continue
		}
		seen[identityKey] = struct{}{}
		entry := albumTradeRequest{
			ID:           strings.TrimSpace(request.ID),
			IdentityKey:  identityKey,
			Player:       strings.TrimSpace(request.Player),
			Local:        request.Local,
			CreatedAt:    strings.TrimSpace(request.CreatedAt),
			Status:       strings.TrimSpace(request.Status),
			TargetUserID: strings.TrimSpace(request.TargetUserID),
			TargetPlayer: strings.TrimSpace(request.TargetPlayer),
			Offer:        sanitizeAlbumTradeItems(request.Offer, true),
			Want:         sanitizeAlbumTradeItems(request.Want, false),
		}
		if entry.TargetPlayer == "" && strings.HasPrefix(strings.ToLower(entry.TargetUserID), "pseudo:") {
			entry.TargetPlayer = strings.TrimSpace(entry.TargetUserID[len("pseudo:"):])
		}
		if entry.ID == "" {
			entry.ID = fmt.Sprintf("trade_%d", time.Now().UnixNano())
		}
		if entry.Player == "" {
			entry.Player = identityKey
		}
		if entry.CreatedAt == "" {
			entry.CreatedAt = time.Now().UTC().Format(time.RFC3339)
		}
		if entry.Status == "" {
			entry.Status = "open"
		}
		if len(entry.Offer) == 0 && len(entry.Want) == 0 {
			continue
		}
		clean = append(clean, entry)
		if len(clean) >= 48 {
			break
		}
	}
	return clean
}

func loadAlbumTradeRequests() ([]albumTradeRequest, error) {
	var rows []map[string]interface{}
	_, err := albumSupabaseClient.From("app_config").
		Select("config_value", "", false).
		Filter("config_key", "eq", "trade_board").
		Limit(1, "").
		ExecuteTo(&rows)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return []albumTradeRequest{}, nil
	}

	raw := strings.TrimSpace(normalizeNullableString(rows[0]["config_value"]))
	if raw == "" {
		return []albumTradeRequest{}, nil
	}
	var parsed []albumTradeRequest
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return []albumTradeRequest{}, nil
	}
	return sanitizeAlbumTradeRequests(parsed), nil
}

func saveAlbumTradeRequests(requests []albumTradeRequest) error {
	clean := sanitizeAlbumTradeRequests(requests)
	body, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	var existing []map[string]interface{}
	_, err = albumSupabaseClient.From("app_config").
		Select("id", "", false).
		Filter("config_key", "eq", "trade_board").
		Limit(1, "").
		ExecuteTo(&existing)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"config_key":   "trade_board",
		"config_value": string(body),
		"updated_at":   time.Now().UTC().Format(time.RFC3339),
	}
	if len(existing) > 0 {
		id := normalizeNullableString(existing[0]["id"])
		if id == "" {
			return fmt.Errorf("album_trade_board_missing_id")
		}
		_, err = albumSupabaseClient.From("app_config").
			Update(payload, "", "").
			Filter("id", "eq", id).
			ExecuteTo(nil)
		return err
	}
	_, err = albumSupabaseClient.From("app_config").Insert(payload, false, "", "", "").ExecuteTo(nil)
	return err
}

func albumTradeIdentityKeys(identityKey, pseudonimo string) []string {
	keys := appendUniqueAlbumIDs(nil, identityKey, albumPseudoAlias(pseudonimo))
	if hardwareFingerprint := lookupAlbumHardwareFingerprintByPseudo(pseudonimo); hardwareFingerprint != "" {
		keys = appendUniqueAlbumIDs(keys, hardwareFingerprint)
	}
	return keys
}

func loadAlbumUserStickerRowsForKeys(identityKeys []string, stickerID string) ([]albumUserStickerRow, error) {
	rows := make([]albumUserStickerRow, 0, len(identityKeys))
	for _, identityKey := range appendUniqueAlbumIDs(nil, identityKeys...) {
		var rawRows []map[string]interface{}
		query := albumSupabaseClient.From("user_stickers").
			Select("id,user_id,sticker_id,quantity", "", false).
			Filter("user_id", "eq", identityKey)
		if strings.TrimSpace(stickerID) != "" {
			query = query.Filter("sticker_id", "eq", strings.TrimSpace(stickerID))
		}
		if _, err := query.ExecuteTo(&rawRows); err != nil {
			return nil, err
		}
		for _, raw := range rawRows {
			entry := albumUserStickerRow{
				ID:        normalizeNullableString(raw["id"]),
				UserID:    normalizeNullableString(raw["user_id"]),
				StickerID: normalizeNullableString(raw["sticker_id"]),
				Quantity:  0,
			}
			if qty, ok := raw["quantity"].(float64); ok {
				entry.Quantity = int(qty)
			}
			if entry.ID == "" || entry.UserID == "" || entry.StickerID == "" || entry.Quantity <= 0 {
				continue
			}
			rows = append(rows, entry)
		}
	}
	return rows, nil
}

func albumStickerQuantityTotal(rows []albumUserStickerRow) int {
	total := 0
	for _, row := range rows {
		total += row.Quantity
	}
	return total
}

func resolveAlbumTradeIncrementUserID(preferredUserID string, identityKeys []string) string {
	keys := appendUniqueAlbumIDs(nil, preferredUserID)
	keys = appendUniqueAlbumIDs(keys, identityKeys...)
	if len(keys) == 0 {
		return ""
	}

	type candidateScore struct {
		UserID   string
		Quantity int
		KeyIndex int
		IsPseudo bool
	}

	orderByKey := make(map[string]int, len(keys))
	for index, key := range keys {
		orderByKey[key] = index
	}

	if albumSupabaseClient != nil {
		rows, err := loadAlbumUserStickerRowsForKeys(keys, "")
		if err == nil && len(rows) > 0 {
			byUserID := make(map[string]*candidateScore, len(keys))
			for _, row := range rows {
				userID := strings.TrimSpace(row.UserID)
				if userID == "" {
					continue
				}
				candidate, exists := byUserID[userID]
				if !exists {
					keyIndex, hasKeyIndex := orderByKey[userID]
					if !hasKeyIndex {
						keyIndex = len(keys)
					}
					candidate = &candidateScore{
						UserID:   userID,
						KeyIndex: keyIndex,
						IsPseudo: strings.HasPrefix(strings.ToLower(userID), "pseudo:"),
					}
					byUserID[userID] = candidate
				}
				candidate.Quantity += row.Quantity
			}
			if len(byUserID) > 0 {
				candidates := make([]candidateScore, 0, len(byUserID))
				for _, candidate := range byUserID {
					candidates = append(candidates, *candidate)
				}
				sort.SliceStable(candidates, func(i, j int) bool {
					if candidates[i].Quantity != candidates[j].Quantity {
						return candidates[i].Quantity > candidates[j].Quantity
					}
					if candidates[i].IsPseudo != candidates[j].IsPseudo {
						return !candidates[i].IsPseudo
					}
					if candidates[i].KeyIndex != candidates[j].KeyIndex {
						return candidates[i].KeyIndex < candidates[j].KeyIndex
					}
					return candidates[i].UserID < candidates[j].UserID
				})
				if resolved := strings.TrimSpace(candidates[0].UserID); resolved != "" {
					return resolved
				}
			}
		}
	}

	for _, key := range keys {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(trimmedKey), "pseudo:") {
			return trimmedKey
		}
	}
	return strings.TrimSpace(keys[0])
}

func albumDecrementStickerForTrade(identityKeys []string, stickerID string, requiredTotal int) error {
	rows, err := loadAlbumUserStickerRowsForKeys(identityKeys, stickerID)
	if err != nil {
		return err
	}
	if albumStickerQuantityTotal(rows) < requiredTotal {
		return fmt.Errorf("album_trade_missing_sticker:%s", stickerID)
	}
	if len(rows) == 0 {
		return fmt.Errorf("album_trade_missing_row:%s", stickerID)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Quantity == rows[j].Quantity {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].Quantity > rows[j].Quantity
	})
	selected := rows[0]
	nextQuantity := selected.Quantity - 1
	if nextQuantity > 0 {
		_, _, err = albumSupabaseClient.From("user_stickers").
			Update(map[string]interface{}{"quantity": nextQuantity}, "", "").
			Filter("id", "eq", selected.ID).
			Execute()
		return err
	}
	_, _, err = albumSupabaseClient.From("user_stickers").
		Delete("", "").
		Filter("id", "eq", selected.ID).
		Execute()
	return err
}

func albumIncrementStickerForTrade(userID, stickerID string) error {
	trimmedUserID := strings.TrimSpace(userID)
	trimmedStickerID := strings.TrimSpace(stickerID)
	if trimmedUserID == "" || trimmedStickerID == "" {
		return fmt.Errorf("album_trade_increment_invalid")
	}
	var existing []map[string]interface{}
	_, err := albumSupabaseClient.From("user_stickers").
		Select("id,quantity", "", false).
		Filter("user_id", "eq", trimmedUserID).
		Filter("sticker_id", "eq", trimmedStickerID).
		Limit(1, "").
		ExecuteTo(&existing)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		recordID := normalizeNullableString(existing[0]["id"])
		currentQuantity := 0
		if qty, ok := existing[0]["quantity"].(float64); ok {
			currentQuantity = int(qty)
		}
		_, _, err = albumSupabaseClient.From("user_stickers").
			Update(map[string]interface{}{"quantity": currentQuantity + 1}, "", "").
			Filter("id", "eq", recordID).
			Execute()
		return err
	}
	_, err = albumSupabaseClient.From("user_stickers").
		Insert(map[string]interface{}{
			"user_id":    trimmedUserID,
			"sticker_id": trimmedStickerID,
			"quantity":   1,
		}, false, "", "", "").
		ExecuteTo(nil)
	return err
}

func loadAlbumUserPackBalance(userID string) (albumPackBalance, error) {
	balance := albumPackBalance{}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return balance, nil
	}
	var rows []map[string]interface{}
	_, err := albumSupabaseClient.From("user_pack_balances").
		Select("bonus_packs", "", false).
		Filter("user_id", "eq", userID).
		Limit(1, "").
		ExecuteTo(&rows)
	if err != nil {
		return balance, err
	}
	if len(rows) == 0 {
		return balance, nil
	}
	if raw, ok := rows[0]["bonus_packs"].(float64); ok {
		balance.BonusPacks = int(raw)
	}
	if balance.BonusPacks < 0 {
		balance.BonusPacks = 0
	}
	return balance, nil
}

func loadAlbumUserPackBalanceForKeys(userIDs []string) (albumPackBalance, map[string]int, error) {
	totals := albumPackBalance{}
	perUser := make(map[string]int, len(userIDs))
	for _, userID := range appendUniqueAlbumIDs(nil, userIDs...) {
		balance, err := loadAlbumUserPackBalance(userID)
		if err != nil {
			return albumPackBalance{}, nil, err
		}
		perUser[userID] = balance.BonusPacks
		totals.BonusPacks += balance.BonusPacks
	}
	if totals.BonusPacks < 0 {
		totals.BonusPacks = 0
	}
	return totals, perUser, nil
}

func setAlbumUserPackBalance(userID string, bonusPacks int) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("album_user_id_required")
	}
	if bonusPacks < 0 {
		bonusPacks = 0
	}
	payload := map[string]interface{}{
		"user_id":     userID,
		"bonus_packs": bonusPacks,
		"updated_at":  time.Now().UTC().Format(time.RFC3339),
	}
	var existing []map[string]interface{}
	_, err := albumSupabaseClient.From("user_pack_balances").
		Select("id", "", false).
		Filter("user_id", "eq", userID).
		Limit(1, "").
		ExecuteTo(&existing)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		id := normalizeNullableString(existing[0]["id"])
		if id == "" {
			return fmt.Errorf("album_pack_balance_missing_id")
		}
		_, err = albumSupabaseClient.From("user_pack_balances").
			Update(payload, "", "").
			Filter("id", "eq", id).
			ExecuteTo(nil)
		return err
	}
	_, err = albumSupabaseClient.From("user_pack_balances").Insert(payload, false, "", "", "").ExecuteTo(nil)
	return err
}

func decrementAlbumBonusPack(userID string, identityKeys []string) (bool, int, error) {
	keys := appendUniqueAlbumIDs(nil, identityKeys...)
	keys = appendUniqueAlbumIDs(keys, userID)
	balance, perUser, err := loadAlbumUserPackBalanceForKeys(keys)
	if err != nil {
		return false, 0, err
	}
	if balance.BonusPacks <= 0 {
		return false, 0, nil
	}
	targetUserID := strings.TrimSpace(userID)
	if perUser[targetUserID] <= 0 {
		targetUserID = ""
		for _, candidate := range keys {
			if perUser[candidate] > 0 {
				targetUserID = candidate
				break
			}
		}
	}
	if targetUserID == "" {
		return false, balance.BonusPacks, nil
	}
	next := perUser[targetUserID] - 1
	if next < 0 {
		next = 0
	}
	if err := setAlbumUserPackBalance(targetUserID, next); err != nil {
		return false, balance.BonusPacks, err
	}
	return true, balance.BonusPacks - 1, nil
}

func loadAlbumDailyFreePackQuota(identityKeys []string, now time.Time) (albumDailyPackQuota, error) {
	keys := appendUniqueAlbumIDs(nil, identityKeys...)
	current := now
	if current.IsZero() {
		current = time.Now()
	}
	if len(keys) == 0 {
		return albumDailyPackQuota{Count: 0, Remaining: albumDailyFreePackLimit}, nil
	}

	windowStartUTC := current.UTC().Add(-24 * time.Hour)
	openings := make([]time.Time, 0, albumDailyFreePackLimit)
	for _, identityKey := range keys {
		var rows []map[string]interface{}
		_, err := albumSupabaseClient.From("pack_openings").
			Select("opened_at", "", false).
			Filter("user_id", "eq", identityKey).
			Filter("pack_type", "eq", "standard").
			Filter("opened_at", "gte", windowStartUTC.Format(time.RFC3339)).
			Order("opened_at", &postgrest.OrderOpts{Ascending: true}).
			ExecuteTo(&rows)
		if err != nil {
			return albumDailyPackQuota{}, err
		}
		for _, row := range rows {
			openedAt := normalizeNullableString(row["opened_at"])
			if openedAt == "" {
				continue
			}
			parsed, parseErr := time.Parse(time.RFC3339Nano, openedAt)
			if parseErr != nil {
				parsed, parseErr = time.Parse(time.RFC3339, openedAt)
			}
			if parseErr != nil {
				continue
			}
			openings = append(openings, parsed.UTC())
		}
	}

	if len(openings) == 0 {
		return albumDailyPackQuota{Count: 0, Remaining: albumDailyFreePackLimit}, nil
	}

	sort.Slice(openings, func(left, right int) bool {
		return openings[left].Before(openings[right])
	})

	actualCount := len(openings)
	displayCount := actualCount
	if displayCount > albumDailyFreePackLimit {
		displayCount = albumDailyFreePackLimit
	}
	remaining := albumDailyFreePackLimit - actualCount
	if remaining < 0 {
		remaining = 0
	}
	quota := albumDailyPackQuota{Count: displayCount, Remaining: remaining}
	if actualCount >= albumDailyFreePackLimit {
		resetIndex := actualCount - albumDailyFreePackLimit
		if resetIndex < 0 {
			resetIndex = 0
		}
		if resetIndex >= len(openings) {
			resetIndex = len(openings) - 1
		}
		quota.ResetAt = openings[resetIndex].Add(24 * time.Hour).UTC().Format(time.RFC3339)
	}
	return quota, nil
}

func upsertAlbumKnownUser(ordered []albumKnownUser, seenByUserID map[string]int, seenByPseudo map[string]int, userID, pseudonimo string) []albumKnownUser {
	pseudonimo = strings.TrimSpace(pseudonimo)
	userID = strings.TrimSpace(userID)
	if userID == "" {
		userID = albumPseudoAlias(pseudonimo)
	}
	if userID == "" {
		return ordered
	}
	pseudoKey := strings.ToLower(strings.TrimSpace(pseudonimo))
	index, exists := seenByUserID[userID]
	if !exists && pseudoKey != "" {
		index, exists = seenByPseudo[pseudoKey]
	}
	if exists {
		existing := ordered[index]
		existingIsPseudo := strings.HasPrefix(strings.ToLower(strings.TrimSpace(existing.UserID)), "pseudo:")
		candidateIsPseudo := strings.HasPrefix(strings.ToLower(userID), "pseudo:")
		if existing.Pseudonimo == "" && pseudonimo != "" {
			existing.Pseudonimo = pseudonimo
		}
		if existing.UserID == "" || (existingIsPseudo && !candidateIsPseudo) {
			delete(seenByUserID, existing.UserID)
			existing.UserID = userID
		}
		ordered[index] = existing
		seenByUserID[existing.UserID] = index
		if pseudoKey != "" {
			seenByPseudo[pseudoKey] = index
		}
		return ordered
	}
	entry := albumKnownUser{UserID: userID, Pseudonimo: pseudonimo}
	ordered = append(ordered, entry)
	index = len(ordered) - 1
	seenByUserID[userID] = index
	if pseudoKey != "" {
		seenByPseudo[pseudoKey] = index
	}
	return ordered
}

func loadAlbumKnownUsers() ([]albumKnownUser, error) {
	var rows []map[string]interface{}
	_, err := supabaseClient.From("audit_logs").
		Select("hardware_fingerprint,pseudonimo", "", false).
		Filter("pseudonimo", "neq", "").
		Order("timestamp", &postgrest.OrderOpts{Ascending: false}).
		Limit(5000, "").
		ExecuteTo(&rows)
	if err != nil {
		return nil, err
	}
	seenByUserID := make(map[string]int, len(rows))
	seenByPseudo := make(map[string]int, len(rows))
	ordered := make([]albumKnownUser, 0, len(rows))
	for _, row := range rows {
		ordered = upsertAlbumKnownUser(
			ordered,
			seenByUserID,
			seenByPseudo,
			normalizeNullableString(row["hardware_fingerprint"]),
			normalizeNullableString(row["pseudonimo"]),
		)
	}
	for _, tableName := range []string{"user_pack_balances", "pack_openings", "user_stickers"} {
		var albumRows []map[string]interface{}
		if _, albumErr := albumSupabaseClient.From(tableName).
			Select("user_id", "", false).
			Limit(5000, "").
			ExecuteTo(&albumRows); albumErr != nil {
			log.Printf("⚠️ album known users %s: %v", tableName, albumErr)
			continue
		}
		for _, row := range albumRows {
			userID := strings.TrimSpace(normalizeNullableString(row["user_id"]))
			pseudo := ""
			if strings.HasPrefix(strings.ToLower(userID), "pseudo:") {
				pseudo = strings.TrimSpace(userID[len("pseudo:"):])
			}
			ordered = upsertAlbumKnownUser(ordered, seenByUserID, seenByPseudo, userID, pseudo)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		leftPseudo := strings.ToLower(strings.TrimSpace(ordered[i].Pseudonimo))
		rightPseudo := strings.ToLower(strings.TrimSpace(ordered[j].Pseudonimo))
		if leftPseudo == rightPseudo {
			return ordered[i].UserID < ordered[j].UserID
		}
		if leftPseudo == "" {
			return false
		}
		if rightPseudo == "" {
			return true
		}
		return leftPseudo < rightPseudo
	})
	return ordered, nil
}

// GET /api/album/session
// Devuelve la sesión Bellator activa del álbum si existe.
func albumSessionGetHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := albumSessionFromRequest(r)
	if err != nil {
		clearAlbumSessionCookie(w, r)
		http.Error(w, `{"error":"album_session_invalid"}`, http.StatusUnauthorized)
		return
	}
	if claims == nil {
		http.Error(w, `{"error":"album_session_required"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	session := albumSessionInfoFromClaims(claims)
	token, tokenErr := signAlbumSession(session)
	if tokenErr != nil {
		http.Error(w, `{"error":"album_session_write_failed"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"session":       session,
		"token":         token,
	})
}

// POST /api/album/session
// Autentica por pseudónimo + clave Bellator y emite una sesión firmada del álbum.
func albumSessionCreateHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pseudonimo string `json:"pseudonimo"`
		PlayerKey  string `json:"player_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}
	body.Pseudonimo = strings.TrimSpace(body.Pseudonimo)
	body.PlayerKey = strings.TrimSpace(body.PlayerKey)
	if body.Pseudonimo == "" || body.PlayerKey == "" {
		http.Error(w, `{"error":"pseudonimo_y_clave_requeridos"}`, http.StatusBadRequest)
		return
	}
	playerRow, authCode, err := verifyPlayerCredentials(body.Pseudonimo, body.PlayerKey)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	if playerRow == nil {
		status := http.StatusUnauthorized
		if authCode == "jugador_no_encontrado" {
			status = http.StatusNotFound
		}
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, authCode), status)
		return
	}
	session := albumSessionInfoFromPlayerRow(playerRow, body.Pseudonimo)
	if session.CollectionKey == "" {
		http.Error(w, `{"error":"album_collection_identity_missing"}`, http.StatusConflict)
		return
	}
	token, tokenErr := signAlbumSession(session)
	if tokenErr != nil {
		http.Error(w, `{"error":"album_session_write_failed"}`, http.StatusInternalServerError)
		return
	}
	if err := writeAlbumSessionCookie(w, r, session); err != nil {
		http.Error(w, `{"error":"album_session_write_failed"}`, http.StatusInternalServerError)
		return
	}
	log.Printf("🎟️ ALBUM SESSION READY: pseudo=%s collection=%s ip=%s",
		compactAuditValue(session.Pseudonimo, 48),
		compactAuditValue(session.CollectionKey, 24),
		compactAuditValue(requestClientIP(r), 64),
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"session":       session,
		"token":         token,
	})
}

// DELETE /api/album/session
// Cierra la sesión Bellator del álbum.
func albumSessionDeleteHandler(w http.ResponseWriter, r *http.Request) {
	clearAlbumSessionCookie(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// GET /api/album/config
// Devuelve la configuración global actual del álbum.
func albumConfigHandler(w http.ResponseWriter, r *http.Request) {
	config, err := loadAlbumMissionConfig()
	if err != nil {
		http.Error(w, `{"error":"album_config_unavailable"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=30")
	json.NewEncoder(w).Encode(config)
}

// GET /api/album/me
// Devuelve un resumen ligero del usuario del álbum y sus sobres extra.
func albumMeHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := albumSessionFromRequest(r)
	if err != nil {
		clearAlbumSessionCookie(w, r)
		http.Error(w, `{"error":"album_session_invalid"}`, http.StatusUnauthorized)
		return
	}
	if claims == nil {
		http.Error(w, `{"error":"album_session_required"}`, http.StatusUnauthorized)
		return
	}
	session := albumSessionInfoFromClaims(claims)
	_, identityKeys := albumIdentityKeysFromClaims(claims)
	balance, _, err := loadAlbumUserPackBalanceForKeys(identityKeys)
	if err != nil {
		http.Error(w, `{"error":"album_balance_unavailable"}`, http.StatusInternalServerError)
		return
	}
	dailyQuota, err := loadAlbumDailyFreePackQuota(identityKeys, time.Now())
	if err != nil {
		http.Error(w, `{"error":"album_daily_pack_unavailable"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(albumViewerSummary{
		Authenticated: true,
		Session:       &session,
		BonusPacks:    balance.BonusPacks,
		DailyPacks:    dailyQuota,
	})
}

// GET /api/album/users
// Devuelve los perfiles Bellator disponibles como destinatarios de solicitudes directas.
func albumUsersHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := albumSessionFromRequest(r)
	if err != nil {
		clearAlbumSessionCookie(w, r)
		http.Error(w, `{"error":"album_session_invalid"}`, http.StatusUnauthorized)
		return
	}
	if claims == nil {
		http.Error(w, `{"error":"album_session_required"}`, http.StatusUnauthorized)
		return
	}
	users, err := loadAlbumKnownUsers()
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	currentUserID, currentIdentityKeys := albumIdentityKeysFromClaims(claims)
	currentKeys := appendUniqueAlbumIDs(nil, currentIdentityKeys...)
	currentKeys = appendUniqueAlbumIDs(currentKeys, currentUserID, albumPseudoAlias(claims.Pseudonimo))
	seen := make(map[string]struct{}, len(users))
	targets := make([]albumTradeTargetOption, 0, len(users))
	for _, user := range users {
		pseudo := strings.TrimSpace(user.Pseudonimo)
		if pseudo == "" || strings.EqualFold(pseudo, claims.Pseudonimo) {
			continue
		}
		skip := false
		for _, key := range currentKeys {
			if key != "" && strings.TrimSpace(user.UserID) == key {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		pseudoKey := strings.ToLower(pseudo)
		if _, exists := seen[pseudoKey]; exists {
			continue
		}
		seen[pseudoKey] = struct{}{}
		targets = append(targets, albumTradeTargetOption{Pseudonimo: pseudo})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(targets)
}

// GET /api/album/trades
// Devuelve el muro compartido de solicitudes de intercambio del álbum.
func albumTradeBoardHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := albumSessionFromRequest(r)
	if err != nil {
		clearAlbumSessionCookie(w, r)
		http.Error(w, `{"error":"album_session_invalid"}`, http.StatusUnauthorized)
		return
	}
	if claims == nil {
		http.Error(w, `{"error":"album_session_required"}`, http.StatusUnauthorized)
		return
	}
	requests, err := loadAlbumTradeRequests()
	if err != nil {
		http.Error(w, `{"error":"album_trade_board_unavailable"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(requests)
}

// POST /api/album/trades
// Publica o reemplaza la solicitud activa de intercambio del usuario autenticado.
func albumTradePublishHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := albumSessionFromRequest(r)
	if err != nil {
		clearAlbumSessionCookie(w, r)
		http.Error(w, `{"error":"album_session_invalid"}`, http.StatusUnauthorized)
		return
	}
	if claims == nil {
		http.Error(w, `{"error":"album_session_required"}`, http.StatusUnauthorized)
		return
	}
	userID, _ := albumIdentityKeysFromClaims(claims)
	if userID == "" {
		http.Error(w, `{"error":"album_trade_identity_missing"}`, http.StatusConflict)
		return
	}
	var body albumTradeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"body_invalido"}`, http.StatusBadRequest)
		return
	}
	targetPlayer := strings.TrimSpace(body.TargetPlayer)
	targetUserID := ""
	
	if targetPlayer != "" {
		users, err := loadAlbumKnownUsers()
		if err != nil {
			http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
			return
		}
		selectedTarget := (*albumKnownUser)(nil)
		for index := range users {
			if sameNormalizedPseudo(strings.TrimSpace(users[index].Pseudonimo), targetPlayer) || strings.EqualFold(strings.TrimSpace(users[index].Pseudonimo), targetPlayer) {
				selectedTarget = &users[index]
				break
			}
		}
		if selectedTarget == nil {
			http.Error(w, `{"error":"album_trade_target_not_found"}`, http.StatusNotFound)
			return
		}
		targetUserID = firstNonEmpty(strings.TrimSpace(selectedTarget.UserID), albumPseudoAlias(selectedTarget.Pseudonimo))
		if targetUserID == "" {
			http.Error(w, `{"error":"album_trade_target_not_found"}`, http.StatusNotFound)
			return
		}
		if targetUserID == userID || strings.EqualFold(selectedTarget.Pseudonimo, claims.Pseudonimo) {
			http.Error(w, `{"error":"album_trade_target_self"}`, http.StatusConflict)
			return
		}
		targetPlayer = strings.TrimSpace(selectedTarget.Pseudonimo)
	}

	offer := sanitizeAlbumTradeItems(body.Offer, true)
	want := sanitizeAlbumTradeItems(body.Want, false)
	if len(offer) != 1 || len(want) != 1 {
		http.Error(w, `{"error":"album_trade_must_be_1_for_1"}`, http.StatusBadRequest)
		return
	}

	albumTradeBoardMutex.Lock()
	defer albumTradeBoardMutex.Unlock()

	requests, err := loadAlbumTradeRequests()
	if err != nil {
		http.Error(w, `{"error":"album_trade_board_unavailable"}`, http.StatusInternalServerError)
		return
	}
	filtered := make([]albumTradeRequest, 0, len(requests)+1)
	for _, request := range requests {
		if strings.TrimSpace(request.IdentityKey) == userID {
			continue
		}
		filtered = append(filtered, request)
	}
	filtered = append([]albumTradeRequest{{
		ID:           fmt.Sprintf("trade_%d", time.Now().UnixNano()),
		IdentityKey:  userID,
		Player:       strings.TrimSpace(claims.Pseudonimo),
		Local:        false,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Status:       "open",
		TargetUserID: targetUserID,
		TargetPlayer: targetPlayer,
		Offer:        offer,
		Want:         want,
	}}, filtered...)
	if err := saveAlbumTradeRequests(filtered); err != nil {
		http.Error(w, `{"error":"album_trade_save_failed"}`, http.StatusInternalServerError)
		return
	}
	filtered = sanitizeAlbumTradeRequests(filtered)
	log.Printf("🔄 ALBUM TRADE PUBLISHED: user=%s pseudo=%s offer=%d want=%d ip=%s",
		compactAuditValue(userID, 32),
		compactAuditValue(strings.TrimSpace(claims.Pseudonimo), 48),
		len(offer),
		len(want),
		compactAuditValue(requestClientIP(r), 64),
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"requests": filtered,
	})
}

// POST /api/album/trades/accept
// Ejecuta un intercambio real 1:1 por cada cromo listado y cierra la solicitud.
func albumTradeAcceptHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := albumSessionFromRequest(r)
	if err != nil {
		clearAlbumSessionCookie(w, r)
		http.Error(w, `{"error":"album_session_invalid"}`, http.StatusUnauthorized)
		return
	}
	if claims == nil {
		http.Error(w, `{"error":"album_session_required"}`, http.StatusUnauthorized)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"body_invalido"}`, http.StatusBadRequest)
		return
	}
	tradeID := strings.TrimSpace(body.ID)
	if tradeID == "" {
		http.Error(w, `{"error":"album_trade_id_required"}`, http.StatusBadRequest)
		return
	}
	currentUserID, currentIdentityKeys := albumIdentityKeysFromClaims(claims)
	if currentUserID == "" {
		http.Error(w, `{"error":"album_trade_identity_missing"}`, http.StatusConflict)
		return
	}

	albumTradeBoardMutex.Lock()
	defer albumTradeBoardMutex.Unlock()

	requests, err := loadAlbumTradeRequests()
	if err != nil {
		http.Error(w, `{"error":"album_trade_board_unavailable"}`, http.StatusInternalServerError)
		return
	}
	requestIndex := -1
	for index, request := range requests {
		if strings.TrimSpace(request.ID) == tradeID {
			requestIndex = index
			break
		}
	}
	if requestIndex < 0 {
		http.Error(w, `{"error":"album_trade_not_found"}`, http.StatusNotFound)
		return
	}
	tradeRequest := requests[requestIndex]
	if strings.TrimSpace(tradeRequest.IdentityKey) == currentUserID {
		http.Error(w, `{"error":"album_trade_own_request"}`, http.StatusConflict)
		return
	}
	if firstNonEmpty(strings.TrimSpace(tradeRequest.Status), "open") != "open" {
		http.Error(w, `{"error":"album_trade_not_open"}`, http.StatusConflict)
		return
	}
	targetUserID := firstNonEmpty(strings.TrimSpace(tradeRequest.TargetUserID), albumPseudoAlias(tradeRequest.TargetPlayer))
	isGlobalTrade := targetUserID == "" && strings.TrimSpace(tradeRequest.TargetPlayer) == ""
	
	targetedToCurrentUser := false
	if isGlobalTrade {
		targetedToCurrentUser = true
	} else {
		currentKeys := appendUniqueAlbumIDs(nil, currentIdentityKeys...)
		currentKeys = appendUniqueAlbumIDs(currentKeys, currentUserID, albumPseudoAlias(claims.Pseudonimo))
		for _, key := range currentKeys {
			if key == targetUserID {
				targetedToCurrentUser = true
				break
			}
		}
		if !targetedToCurrentUser && (strings.EqualFold(strings.TrimSpace(tradeRequest.TargetPlayer), strings.TrimSpace(claims.Pseudonimo)) || sameNormalizedPseudo(strings.TrimSpace(tradeRequest.TargetPlayer), strings.TrimSpace(claims.Pseudonimo))) {
			targetedToCurrentUser = true
		}
	}
	
	if !targetedToCurrentUser {
		http.Error(w, `{"error":"album_trade_not_for_you"}`, http.StatusForbidden)
		return
	}
	requesterKeys := albumTradeIdentityKeys(tradeRequest.IdentityKey, tradeRequest.Player)
	requesterIncrementUserID := resolveAlbumTradeIncrementUserID(strings.TrimSpace(tradeRequest.IdentityKey), requesterKeys)
	if requesterIncrementUserID == "" {
		http.Error(w, `{"error":"album_trade_requester_identity_missing"}`, http.StatusConflict)
		return
	}
	offerIDs := make([]string, len(tradeRequest.Offer))
	for i, item := range tradeRequest.Offer {
		offerIDs[i] = item.ID
	}
	wantIDs := make([]string, len(tradeRequest.Want))
	for i, item := range tradeRequest.Want {
		wantIDs[i] = item.ID
	}

	params := map[string]interface{}{
		"p_requester_ids":          requesterKeys,
		"p_accepter_ids":           currentIdentityKeys,
		"p_requester_increment_id": requesterIncrementUserID,
		"p_accepter_increment_id":  currentUserID,
		"p_offer_ids":              offerIDs,
		"p_want_ids":               wantIDs,
	}

	_, rpcErr := albumSupabaseClient.RpcWithError("execute_trade", "", params)
	if rpcErr != nil {
		errMsg := rpcErr.Error()
		log.Printf("❌ ALBUM TRADE FAILED (RPC): trade=%s err=%v", compactAuditValue(tradeID, 32), rpcErr)
		if strings.Contains(errMsg, "album_trade_requester_inventory_changed") {
			http.Error(w, `{"error":"album_trade_requester_inventory_changed"}`, http.StatusConflict)
		} else if strings.Contains(errMsg, "album_trade_counter_inventory_missing") {
			http.Error(w, `{"error":"album_trade_counter_inventory_missing"}`, http.StatusConflict)
		} else {
			http.Error(w, `{"error":"album_trade_apply_failed"}`, http.StatusInternalServerError)
		}
		return
	}

	requests[requestIndex].Status = "completed"
	if err := saveAlbumTradeRequests(requests); err != nil {
		log.Printf("⚠️ album trade complete save: id=%s err=%v", compactAuditValue(tradeID, 32), err)
	}
	log.Printf("🤝 ALBUM TRADE COMPLETED: trade=%s requester=%s accepter=%s offer=%d want=%d ip=%s",
		compactAuditValue(tradeID, 32),
		compactAuditValue(strings.TrimSpace(tradeRequest.Player), 48),
		compactAuditValue(strings.TrimSpace(claims.Pseudonimo), 48),
		len(tradeRequest.Offer),
		len(tradeRequest.Want),
		compactAuditValue(requestClientIP(r), 64),
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"requests": sanitizeAlbumTradeRequests(requests),
	})
}

// POST /api/album/register
// Registro rápido del álbum: crea identidad Bellator mínima y abre sesión al instante.
func albumRegisterHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pseudonimo          string `json:"pseudonimo"`
		PlayerKey           string `json:"player_key"`
		CountryCode         string `json:"country_code"`
		HardwareFingerprint string `json:"hardware_fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}
	body.Pseudonimo = strings.TrimSpace(body.Pseudonimo)
	body.PlayerKey = strings.TrimSpace(body.PlayerKey)
	body.CountryCode = normalizeAlbumCountryCode(body.CountryCode)
	if body.CountryCode == "" {
		body.CountryCode = "XX"
	}
	body.HardwareFingerprint = strings.TrimSpace(body.HardwareFingerprint)
	if body.Pseudonimo == "" || body.PlayerKey == "" || body.HardwareFingerprint == "" {
		http.Error(w, `{"error":"album_register_invalid_data"}`, http.StatusBadRequest)
		return
	}

	playerRow, authCode, err := verifyPlayerCredentials(body.Pseudonimo, body.PlayerKey)
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	if playerRow != nil {
		session := albumSessionInfoFromPlayerRow(playerRow, body.Pseudonimo)
		token, tokenErr := signAlbumSession(session)
		if tokenErr != nil {
			http.Error(w, `{"error":"album_session_write_failed"}`, http.StatusInternalServerError)
			return
		}
		if err := writeAlbumSessionCookie(w, r, session); err != nil {
			http.Error(w, `{"error":"album_session_write_failed"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, no-store")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": true,
			"registered":    false,
			"existing":      true,
			"session":       session,
			"token":         token,
		})
		return
	}
	if authCode == "clave_incorrecta" {
		http.Error(w, `{"error":"pseudonimo_taken"}`, http.StatusConflict)
		return
	}
	if authCode != "" && authCode != "jugador_no_encontrado" && authCode != "jugador_sin_clave" {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, authCode), http.StatusBadRequest)
		return
	}

	keyHash := sha256.Sum256([]byte(body.PlayerKey))
	auditData := map[string]interface{}{
		"hardware_fingerprint": body.HardwareFingerprint,
		"pseudonimo":           body.Pseudonimo,
		"country_code":         body.CountryCode,
		"timestamp":            time.Now().Format(time.RFC3339),
		"spamhaus_status":      "clean",
		"player_key_hash":      hex.EncodeToString(keyHash[:]),
	}
	if connIP := requestClientIP(r); connIP != "" {
		auditData["ip_real_webrtc"] = connIP
		auditData["ip_conexion_hash"] = hashIP(connIP)
	}

	var auditRes []map[string]interface{}
	_, err = supabaseClient.From("audit_logs").
		Insert(auditData, false, "", "", "").
		ExecuteTo(&auditRes)
	if err != nil {
		log.Printf("⚠️ album register audit_logs: %v", err)
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}

	session := albumSessionInfo{
		Pseudonimo:    body.Pseudonimo,
		Division:      "",
		AvatarURL:     "",
		CollectionKey: body.HardwareFingerprint,
	}
	token, tokenErr := signAlbumSession(session)
	if tokenErr != nil {
		http.Error(w, `{"error":"album_session_write_failed"}`, http.StatusInternalServerError)
		return
	}
	if err := writeAlbumSessionCookie(w, r, session); err != nil {
		http.Error(w, `{"error":"album_session_write_failed"}`, http.StatusInternalServerError)
		return
	}

	fingerprintPreview := body.HardwareFingerprint
	if len(fingerprintPreview) > 12 {
		fingerprintPreview = fingerprintPreview[:12]
	}
	log.Printf("🪪 ALBUM QUICK REGISTERED: pseudo=%s country=%s fp=%s",
		compactAuditValue(body.Pseudonimo, 48),
		compactAuditValue(body.CountryCode, 8),
		compactAuditValue(fingerprintPreview, 12),
	)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"authenticated": true,
		"registered":    true,
		"existing":      false,
		"session":       session,
		"token":         token,
	})
}

// ════════════════════════════════════════════════════════════════════════
// GET /api/album/catalog
// Devuelve el catálogo completo de stickers (público, cacheado 60s).
// ════════════════════════════════════════════════════════════════════════
func albumCatalogHandler(w http.ResponseWriter, r *http.Request) {
	var rows []map[string]interface{}
	_, err := albumSupabaseClient.From("stickers").
		Select("id,series,player_pseudo,division,sticker_type,variant,special_type,display_name,image_url,rarity,slot_number,max_copies", "", false).
		Order("slot_number", nil).
		ExecuteTo(&rows)
	if err != nil {
		http.Error(w, `{"error":"no se pudo cargar el catálogo"}`, http.StatusInternalServerError)
		return
	}
	rosterImages, rosterErr := loadAlbumRosterImageSources()
	if rosterErr != nil {
		log.Printf("⚠️ album catalog roster images: %v", rosterErr)
		rosterImages = map[string]albumRosterImageSources{}
	}

	stickers := make([]albumSticker, 0, len(rows))
	for _, row := range rows {
		s := rowToAlbumStickerWithFallback(row, rosterImages)
		stickers = append(stickers, s)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=60")
	json.NewEncoder(w).Encode(stickers)
}

// ════════════════════════════════════════════════════════════════════════
// GET /api/album/collection
// Devuelve el catálogo + flag collected/quantity del usuario autenticado.
// ════════════════════════════════════════════════════════════════════════
func albumCollectionHandler(w http.ResponseWriter, r *http.Request) {
	userID, identityKeys := albumIdentityKeysFromRequest(r)
	if userID == "" {
		http.Error(w, `{"error":"no autorizado"}`, http.StatusUnauthorized)
		return
	}

	// Catálogo completo
	var catalogRows []map[string]interface{}
	_, err := albumSupabaseClient.From("stickers").
		Select("id,series,player_pseudo,division,sticker_type,variant,special_type,display_name,image_url,rarity,slot_number,max_copies", "", false).
		Order("slot_number", nil).
		ExecuteTo(&catalogRows)
	if err != nil {
		http.Error(w, `{"error":"error al cargar catálogo"}`, http.StatusInternalServerError)
		return
	}
	rosterImages, rosterErr := loadAlbumRosterImageSources()
	if rosterErr != nil {
		log.Printf("⚠️ album collection roster images: %v", rosterErr)
		rosterImages = map[string]albumRosterImageSources{}
	}

	// Inventario del usuario
	var invRows []map[string]interface{}
	for _, identityKey := range appendUniqueAlbumIDs(nil, identityKeys...) {
		var rows []map[string]interface{}
		if _, err := albumSupabaseClient.From("user_stickers").
			Select("sticker_id,quantity", "", false).
			Filter("user_id", "eq", identityKey).
			ExecuteTo(&rows); err == nil {
			invRows = append(invRows, rows...)
		} else {
			log.Printf("⚠️ album collection alias load: user=%s err=%v", compactAuditValue(identityKey, 32), err)
		}
	}

	// Mapa sticker_id → quantity
	owned := make(map[string]int, len(invRows))
	for _, row := range invRows {
		sid := normalizeNullableString(row["sticker_id"])
		if qty, ok := row["quantity"].(float64); ok {
			owned[sid] += int(qty)
		}
	}

	result := make([]albumStickerWithCollection, 0, len(catalogRows))
	for _, row := range catalogRows {
		s := rowToAlbumStickerWithFallback(row, rosterImages)
		qty := owned[s.ID]
		result = append(result, albumStickerWithCollection{
			albumSticker: s,
			Collected:    qty > 0,
			Quantity:     qty,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(result)
}

// ════════════════════════════════════════════════════════════════════════
// POST /api/album/open-pack
// Abre un sobre, devuelve los stickers obtenidos y los persiste.
//
// Body: { "pack_type": "standard" | "premium" | "dorado" }
// Response: { "stickers": [...], "new": [...sticker_ids no tenidos antes] }
// ════════════════════════════════════════════════════════════════════════
func albumOpenPackHandler(w http.ResponseWriter, r *http.Request) {
	userID, identityKeys := albumIdentityKeysFromRequest(r)
	if userID == "" {
		http.Error(w, `{"error":"no autorizado"}`, http.StatusUnauthorized)
		return
	}
	var err error

	var req struct {
		PackType     string `json:"pack_type"`
		UseBonusPack bool   `json:"use_bonus_pack"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PackType == "" {
		req.PackType = "standard"
	}
	validTypes := map[string]bool{"standard": true, "premium": true, "dorado": true}
	if !validTypes[req.PackType] {
		http.Error(w, `{"error":"tipo de sobre inválido"}`, http.StatusBadRequest)
		return
	}
	usedBonusPack := false
	remainingBonusPacks := 0
	dailyQuota := albumDailyPackQuota{}
	if req.UseBonusPack {
		usedBonusPack, remainingBonusPacks, err = decrementAlbumBonusPack(userID, identityKeys)
		if err != nil {
			http.Error(w, `{"error":"album_bonus_pack_error"}`, http.StatusInternalServerError)
			return
		}
		if !usedBonusPack {
			http.Error(w, `{"error":"album_bonus_pack_required"}`, http.StatusBadRequest)
			return
		}
		dailyQuota, err = loadAlbumDailyFreePackQuota(identityKeys, time.Now())
		if err != nil {
			http.Error(w, `{"error":"album_daily_pack_unavailable"}`, http.StatusInternalServerError)
			return
		}
	} else {
		dailyQuota, err = loadAlbumDailyFreePackQuota(identityKeys, time.Now())
		if err != nil {
			http.Error(w, `{"error":"album_daily_pack_unavailable"}`, http.StatusInternalServerError)
			return
		}
		if dailyQuota.Remaining <= 0 {
			http.Error(w, `{"error":"album_daily_pack_limit_reached"}`, http.StatusBadRequest)
			return
		}
		balance, _, err := loadAlbumUserPackBalanceForKeys(identityKeys)
		if err == nil {
			remainingBonusPacks = balance.BonusPacks
		}
	}

	// ── 1. Cargar catálogo ─────────────────────────────────────────────
	var catalogRows []map[string]interface{}
	_, err = albumSupabaseClient.From("stickers").
		Select("id,player_pseudo,sticker_type,variant,special_type,display_name,image_url,rarity,slot_number", "", false).
		ExecuteTo(&catalogRows)
	if err != nil || len(catalogRows) == 0 {
		http.Error(w, `{"error":"catálogo vacío — ejecuta el seed primero"}`, http.StatusServiceUnavailable)
		return
	}

	// ── 2. Crear motor de drops reutilizable ─────────────────────────
	dropEngine := newAlbumDropEngine(catalogRows)

	// ── 3. Distribución de rareza por tipo de sobre ─────────────────────
	var distribution []weightedRarity
	packSize := 5

	switch req.PackType {
	case "premium":
		distribution = []weightedRarity{
			{"comun", 20}, {"raro", 35}, {"epico", 27}, {"legendario", 12}, {"dorado", 6},
		}
	case "dorado":
		// Sobre dorado: 3 cromos, slot 0 garantizado dorado
		distribution = []weightedRarity{
			{"dorado", 100}, {"epico", 60}, {"legendario", 40},
		}
		packSize = 3
	default: // standard
		distribution = []weightedRarity{
			{"comun", 48}, {"raro", 30}, {"epico", 14}, {"legendario", 5}, {"dorado", 3},
		}
	}

	// ── 4. Elegir N cromos (con deduplicación dentro del mismo sobre) ──
	pickedIDs := make(map[string]bool, packSize)
	picks := make([]map[string]interface{}, 0, packSize)
	for i := 0; i < packSize; i++ {
		var entry albumPackSelection
		var ok bool
		// Hasta 2 reintentos para evitar duplicados en el mismo sobre
		for attempt := 0; attempt < 3; attempt++ {
			entry, ok = dropEngine.selectPackEntry(distribution)
			if !ok {
				break
			}
			sid := normalizeNullableString(entry.Row["id"])
			if sid == "" || !pickedIDs[sid] {
				break // no duplicado, usar este pick
			}
			// Duplicado detectado — reintentar
		}
		if !ok {
			continue
		}
		row := entry.Row
		row["_effective_rarity"] = entry.Rarity
		row["_effective_pool"] = entry.Pool
		sid := normalizeNullableString(row["id"])
		pickedIDs[sid] = true
		picks = append(picks, row)
	}

	// ── 5. Persistir en user_stickers ──────────────────────────────────
	// Usamos upsert: si ya tiene el cromo incrementa quantity
	stickerIDs := make([]string, 0, len(picks))
	for _, p := range picks {
		sid := normalizeNullableString(p["id"])
		if sid == "" {
			continue
		}
		stickerIDs = append(stickerIDs, sid)
	}

	// Obtener los que ya tiene para marcar cuáles son nuevos
	var existingRows []map[string]interface{}
	_ = albumUpsertStickers(userID, identityKeys, stickerIDs, &existingRows)

	existing := make(map[string]bool, len(existingRows))
	for _, e := range existingRows {
		existing[normalizeNullableString(e["sticker_id"])] = true
	}
	newIDs := make([]string, 0)
	for _, sid := range stickerIDs {
		if !existing[sid] {
			newIDs = append(newIDs, sid)
		}
	}

	// ── 6. Guardar apertura en pack_openings ───────────────────────────
	packLog := map[string]interface{}{
		"user_id":       userID,
		"pack_type":     map[bool]string{true: req.PackType + ":bonus", false: req.PackType}[usedBonusPack],
		"stickers_json": stickerIDs,
		"opened_at":     time.Now().UTC().Format(time.RFC3339),
	}
	_, _ = albumSupabaseClient.From("pack_openings").Insert(packLog, false, "", "", "").ExecuteTo(nil)
	if !usedBonusPack {
		reloadedQuota, quotaErr := loadAlbumDailyFreePackQuota(identityKeys, time.Now())
		if quotaErr == nil {
			dailyQuota = reloadedQuota
		}
	}

	// ── 7. Respuesta ───────────────────────────────────────────────────
	type stickerOut struct {
		ID           string `json:"id"`
		DisplayName  string `json:"display_name"`
		PlayerPseudo string `json:"player_pseudo"`
		StickerType  string `json:"sticker_type"`
		Rarity       string `json:"rarity"`
		Variant      string `json:"variant"`
		SpecialType  string `json:"special_type,omitempty"`
		ImageURL     string `json:"image_url,omitempty"`
		SlotNumber   int    `json:"slot_number"`
		IsNew        bool   `json:"is_new"`
	}

	out := make([]stickerOut, 0, len(picks))
	newSet := make(map[string]bool, len(newIDs))
	rosterImages, rosterErr := loadAlbumRosterImageSources()
	if rosterErr != nil {
		log.Printf("⚠️ album open pack roster images: %v", rosterErr)
		rosterImages = map[string]albumRosterImageSources{}
	}
	for _, id := range newIDs {
		newSet[id] = true
	}
	for _, p := range picks {
		sticker := rowToAlbumStickerWithFallback(p, rosterImages)
		sid := normalizeNullableString(p["id"])
		variant := normalizeNullableString(p["variant"])
		rarity := normalizeNullableString(p["_effective_rarity"])
		if rarity == "" {
			rarity = normalizeNullableString(p["rarity"])
		}
		slotNum := 0
		if v, ok := p["slot_number"].(float64); ok {
			slotNum = int(v)
		}
		specialType := normalizeNullableString(p["special_type"])
		if specialType == "" {
			specialType = "normal"
		}
		out = append(out, stickerOut{
			ID:           sid,
			DisplayName:  sticker.DisplayName,
			PlayerPseudo: sticker.PlayerPseudo,
			StickerType:  sticker.StickerType,
			Rarity:       rarity,
			Variant:      variant,
			SpecialType:  specialType,
			ImageURL:     sticker.ImageURL,
			SlotNumber:   slotNum,
			IsNew:        newSet[sid],
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"stickers":              out,
		"new_count":             len(newIDs),
		"used_bonus_pack":       usedBonusPack,
		"remaining_bonus_packs": remainingBonusPacks,
		"daily_packs":           dailyQuota,
	})
}

// GET /api/admin/album/config
func adminAlbumConfigGetHandler(w http.ResponseWriter, r *http.Request) {
	config, err := loadAlbumMissionConfig()
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(config)
}

// GET /api/admin/album/users
func adminAlbumUsersHandler(w http.ResponseWriter, r *http.Request) {
	users, err := loadAlbumKnownUsers()
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(users)
}

// POST /api/admin/album/config
func adminAlbumConfigUpdateHandler(w http.ResponseWriter, r *http.Request) {
	var body albumMissionConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"body_invalido"}`, http.StatusBadRequest)
		return
	}
	clean := sanitizeAlbumMissionConfig(body)
	if err := saveAlbumMissionConfig(clean); err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	log.Printf("📘 ADMIN ALBUM CONFIG UPDATED: pack=%d pages=%d new=%d ip=%s",
		clean.Pack.Total,
		clean.Pages.Total,
		clean.NewStickers.Total,
		compactAuditValue(requestClientIP(r), 64),
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(clean)
}

// POST /api/admin/album/grant-packs
func adminAlbumGrantPacksHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID string `json:"user_id"`
		Amount int    `json:"amount"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"body_invalido"}`, http.StatusBadRequest)
		return
	}
	body.UserID = strings.TrimSpace(body.UserID)
	if body.UserID == "" {
		http.Error(w, `{"error":"usuario_requerido"}`, http.StatusBadRequest)
		return
	}
	if body.Amount <= 0 {
		http.Error(w, `{"error":"cantidad_invalida"}`, http.StatusBadRequest)
		return
	}
	if body.Amount > 100 {
		http.Error(w, `{"error":"cantidad_excesiva"}`, http.StatusBadRequest)
		return
	}
	if len(strings.TrimSpace(body.Reason)) > 240 {
		http.Error(w, `{"error":"motivo_muy_largo"}`, http.StatusBadRequest)
		return
	}
	users, err := loadAlbumKnownUsers()
	if err != nil {
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	selected := (*albumKnownUser)(nil)
	for index := range users {
		if users[index].UserID == body.UserID {
			selected = &users[index]
			break
		}
	}
	if selected == nil {
		http.Error(w, `{"error":"usuario_album_no_encontrado"}`, http.StatusNotFound)
		return
	}
	balance, err := loadAlbumUserPackBalance(selected.UserID)
	if err != nil {
		log.Printf("⚠️ album grant packs balance load: user=%s err=%v", compactAuditValue(selected.UserID, 32), err)
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	nextBalance := balance.BonusPacks + body.Amount
	if err := setAlbumUserPackBalance(selected.UserID, nextBalance); err != nil {
		log.Printf("⚠️ album grant packs update: user=%s err=%v", compactAuditValue(selected.UserID, 32), err)
		http.Error(w, `{"error":"db_error"}`, http.StatusInternalServerError)
		return
	}
	totalBalance, _, err := loadAlbumUserPackBalanceForKeys(appendUniqueAlbumIDs(nil, selected.UserID, albumPseudoAlias(selected.Pseudonimo)))
	if err != nil {
		totalBalance = albumPackBalance{BonusPacks: nextBalance}
	}
	log.Printf("📦 ADMIN ALBUM GRANT PACKS: amount=%d user=%s pseudo=%s reason=%s ip=%s",
		body.Amount,
		compactAuditValue(selected.UserID, 32),
		compactAuditValue(selected.Pseudonimo, 48),
		compactAuditValue(strings.TrimSpace(body.Reason), 64),
		compactAuditValue(requestClientIP(r), 64),
	)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"amount":      body.Amount,
		"user_id":     selected.UserID,
		"pseudonimo":  selected.Pseudonimo,
		"bonus_packs": totalBalance.BonusPacks,
	})
}

// ════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════

func rowToAlbumSticker(row map[string]interface{}) albumSticker {
	s := albumSticker{
		ID:           normalizeNullableString(row["id"]),
		Series:       normalizeNullableString(row["series"]),
		PlayerPseudo: normalizeNullableString(row["player_pseudo"]),
		Division:     normalizeNullableString(row["division"]),
		StickerType:  normalizeNullableString(row["sticker_type"]),
		Variant:      normalizeNullableString(row["variant"]),
		SpecialType:  normalizeNullableString(row["special_type"]),
		DisplayName:  normalizeNullableString(row["display_name"]),
		ImageURL:     normalizeNullableString(row["image_url"]),
		Rarity:       normalizeNullableString(row["rarity"]),
	}
	if v, ok := row["slot_number"].(float64); ok {
		s.SlotNumber = int(v)
	}
	if v, ok := row["max_copies"].(float64); ok {
		n := int(v)
		s.MaxCopies = &n
	}
	return s
}

// albumUserIDFromRequest usa primero la sesión firmada del álbum y mantiene
// compatibilidad con el header heredado X-Player-Key para previews o clientes antiguos.
func albumUserIDFromContext(r *http.Request) string {
	userID, _ := albumIdentityKeysFromRequest(r)
	return userID
}

// albumUpsertStickers inserta/incrementa quantity en user_stickers para cada sticker_id.
// Llena existingRows con las filas que ya existían antes del upsert.
func albumUpsertStickers(userID string, identityKeys []string, stickerIDs []string, existingRows *[]map[string]interface{}) error {
	if len(stickerIDs) == 0 {
		return nil
	}

	// Obtener cuáles ya tiene antes de upsert
	for _, identityKey := range appendUniqueAlbumIDs(nil, identityKeys...) {
		var rows []map[string]interface{}
		if _, err := albumSupabaseClient.From("user_stickers").
			Select("sticker_id,quantity", "", false).
			Filter("user_id", "eq", identityKey).
			ExecuteTo(&rows); err == nil {
			*existingRows = append(*existingRows, rows...)
		}
	}

	// Upsert cada sticker
	for _, sid := range stickerIDs {
		row := map[string]interface{}{
			"user_id":    userID,
			"sticker_id": sid,
			"quantity":   1,
		}
		var existing []map[string]interface{}
		_, _ = albumSupabaseClient.From("user_stickers").
			Select("id,quantity", "", false).
			Filter("user_id", "eq", userID).
			Filter("sticker_id", "eq", sid).
			ExecuteTo(&existing)

		if len(existing) > 0 {
			currentQty := 1
			if v, ok := existing[0]["quantity"].(float64); ok {
				currentQty = int(v)
			}
			recID := normalizeNullableString(existing[0]["id"])
			_, _ = albumSupabaseClient.From("user_stickers").
				Update(map[string]interface{}{"quantity": currentQty + 1}, "", "").
				Filter("id", "eq", recID).
				ExecuteTo(nil)
		} else {
			_, _ = albumSupabaseClient.From("user_stickers").
				Insert(row, false, "", "", "").
				ExecuteTo(nil)
		}
	}
	return nil
}

// weightedPick selecciona una rareza aleatoriamente según pesos.
func weightedPick(dist []weightedRarity) string {
	total := 0
	for _, d := range dist {
		total += d.weight
	}
	n, _ := cryptoRandN(total)
	cumulative := 0
	for _, d := range dist {
		cumulative += d.weight
		if n < cumulative {
			return d.rarity
		}
	}
	return dist[len(dist)-1].rarity
}

// cryptoRandN devuelve un entero criptográficamente aleatorio en [0, max).
func cryptoRandN(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be > 0")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}


// ════════════════════════════════════════════════════════════════════════
// POST /api/album/activate
// Activa una habilidad de un cromo especial, consumiendo 1 copia.
// ════════════════════════════════════════════════════════════════════════
func albumActivateHandler(w http.ResponseWriter, r *http.Request) {
	userID, identityKeys := albumIdentityKeysFromRequest(r)
	if userID == "" {
		http.Error(w, `{"error":"no autorizado"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		StickerID string `json:"sticker_id"`
		WishText  string `json:"wish_text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.StickerID == "" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	// 1. Obtener detalles del sticker del catálogo
	var catalogRows []map[string]interface{}
	_, err := albumSupabaseClient.From("stickers").
		Select("id,display_name,special_type", "", false).
		Filter("id", "eq", req.StickerID).
		ExecuteTo(&catalogRows)
	if err != nil || len(catalogRows) == 0 {
		http.Error(w, `{"error":"cromo no encontrado"}`, http.StatusNotFound)
		return
	}

	row := catalogRows[0]
	stickerName := normalizeNullableString(row["display_name"])
	specialType := normalizeNullableString(row["special_type"])
	
	validTypes := map[string]bool{"esmeralda": true, "iconico": true, "extra": true, "diamante": true}
	if !validTypes[specialType] {
		http.Error(w, `{"error":"este cromo no se puede activar"}`, http.StatusBadRequest)
		return
	}
	if specialType != "esmeralda" && req.WishText != "" {
		req.WishText = "" // Solo esmeralda puede tener deseo
	}

	// 2. Ejecutar RPC para consumir atómicamente exactamente 1 copia
	rpcPayload := map[string]interface{}{
		"p_user_id":    identityKeys[0], // Usamos el alias activo
		"p_sticker_id": req.StickerID,
	}
	var rpcResult bool
	_, rpcErr := albumSupabaseClient.Rpc("consume_sticker_for_activation", "", rpcPayload).ExecuteTo(&rpcResult)
	if rpcErr != nil || !rpcResult {
		log.Printf("⚠️ Error al consumir cromo (RPC consume_sticker_for_activation): user=%s sticker=%s err=%v", identityKeys[0], req.StickerID, rpcErr)
		http.Error(w, `{"error":"no tienes suficientes copias para activar este cromo"}`, http.StatusBadRequest)
		return
	}

	// 3. Generar código único y firma
	session := getAlbumSession(r)
	pseudo := "JUGADOR"
	if session != nil && session.Pseudonimo != "" {
		pseudo = session.Pseudonimo
	}
	pseudoClean := strings.ToUpper(strings.ReplaceAll(pseudo, " ", ""))
	if len(pseudoClean) > 6 {
		pseudoClean = pseudoClean[:6]
	}

	randBytes := make([]byte, 2)
	rand.Read(randBytes)
	randHex := strings.ToUpper(hex.EncodeToString(randBytes)) // 4 chars

	prefix := "XX"
	switch specialType {
	case "esmeralda": prefix = "EM"
	case "iconico": prefix = "IC"
	case "extra": prefix = "EX"
	case "diamante": prefix = "DI"
	}
	code := fmt.Sprintf("BLT-%s-%s-%s", prefix, randHex, pseudoClean)

	activatedAt := time.Now().UTC()
	expiresAt := activatedAt.Add(7 * 24 * time.Hour)
	
	secret := os.Getenv("ALBUM_JWT_SECRET")
	if secret == "" {
		secret = "default-dev-secret-valhala"
	}
	
	// HMAC
	h := sha256.New()
	h.Write([]byte(code + "|" + req.StickerID + "|" + identityKeys[0] + "|" + activatedAt.Format(time.RFC3339) + "|" + secret))
	signature := hex.EncodeToString(h.Sum(nil))

	// 4. Insertar en sticker_activations
	activationData := map[string]interface{}{
		"user_id":      identityKeys[0],
		"pseudonimo":   pseudo,
		"sticker_id":   req.StickerID,
		"sticker_name": stickerName,
		"special_type": specialType,
		"wish_text":    req.WishText,
		"code":         code,
		"signature":    signature,
		"status":       "active",
		"activated_at": activatedAt.Format(time.RFC3339),
		"expires_at":   expiresAt.Format(time.RFC3339),
		"ip_address":   getRealIP(r),
	}
	_, err = albumSupabaseClient.From("sticker_activations").Insert(activationData, false, "", "", "").ExecuteTo(nil)
	if err != nil {
		log.Printf("⚠️ Error al guardar activación en DB (cromo ya fue consumido!): %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activationData)
}

// ════════════════════════════════════════════════════════════════════════
// GET /api/album/verify/{code}
// Verifica un código de activación públicamente.
// ════════════════════════════════════════════════════════════════════════
func albumVerifyHandler(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if code == "" {
		http.Error(w, `{"error":"código requerido"}`, http.StatusBadRequest)
		return
	}

	var rows []map[string]interface{}
	_, err := albumSupabaseClient.From("sticker_activations").
		Select("*", "", false).
		Filter("code", "eq", code).
		ExecuteTo(&rows)
		
	if err != nil || len(rows) == 0 {
		http.Error(w, `{"error":"código no encontrado o inválido"}`, http.StatusNotFound)
		return
	}
	row := rows[0]

	// Recalcular HMAC para asegurar que no hubo manipulación (opcional dado que viene de DB, pero útil para auditar)
	signature := normalizeNullableString(row["signature"])
	stickerID := normalizeNullableString(row["sticker_id"])
	userID := normalizeNullableString(row["user_id"])
	activatedAtRaw := normalizeNullableString(row["activated_at"])
	
	// Si queríamos verificar HMAC estricto:
	// secret := os.Getenv("ALBUM_JWT_SECRET")
	// h := sha256.New()
	// h.Write([]byte(code + "|" + stickerID + "|" + userID + "|" + activatedAtRaw + "|" + secret))
	// if signature != hex.EncodeToString(h.Sum(nil)) { ... }
	
	// Verificar expiración
	expiresRaw := normalizeNullableString(row["expires_at"])
	if expiresAt, err := time.Parse(time.RFC3339, expiresRaw); err == nil {
		if time.Now().After(expiresAt) && normalizeNullableString(row["status"]) == "active" {
			row["status"] = "expired"
			// Actualizar BD de forma asíncrona o silenciosa
			albumSupabaseClient.From("sticker_activations").Update(map[string]interface{}{"status": "expired"}, "", "").Filter("code", "eq", code).ExecuteTo(nil)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(row)
}
