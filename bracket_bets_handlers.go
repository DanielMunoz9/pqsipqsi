package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// Modelos

type BracketResult struct {
	ID           string    `json:"id"`
	Division     string    `json:"division"`
	MatchCode    string    `json:"match_code"`
	WinnerPseudo string    `json:"winner_pseudo"`
	LoserPseudo  string    `json:"loser_pseudo"`
	Round        int       `json:"round"`
	CreatedAt    time.Time `json:"created_at"`
}

type BetFight struct {
	ID           string    `json:"id"`
	FightID      string    `json:"fight_id"`
	Division     string    `json:"division"`
	Label        string    `json:"label"`
	FighterA     string    `json:"fighter_a"`
	FighterB     string    `json:"fighter_b"`
	Status       string    `json:"status"`
	WinnerPseudo *string   `json:"winner_pseudo,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type Bet struct {
	ID             string    `json:"id"`
	UserUsername   string    `json:"user_username"`
	FightID        string    `json:"fight_id"`
	Division       string    `json:"division"`
	PickedPseudo   string    `json:"picked_pseudo"`
	OpponentPseudo string    `json:"opponent_pseudo"`
	SobresAmount   int       `json:"sobres_amount"`
	Status         string    `json:"status"`
	Payout         int       `json:"payout"`
	Multiplier     float64   `json:"multiplier"`
	CreatedAt      time.Time `json:"created_at"`
}

// ==========================================
// ENDPOINTS PÚBLICOS
// ==========================================

func getBracketResultsHandler(w http.ResponseWriter, r *http.Request) {
	if supabaseClient == nil {
		http.Error(w, `{"error":"supabase no configurado"}`, http.StatusInternalServerError)
		return
	}
	res, _, err := supabaseClient.From("bracket_results").Select("*", "", false).Execute()
	if err != nil {
		http.Error(w, `{"error":"error al leer resultados de bracket"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}

func getOpenBetFightsHandler(w http.ResponseWriter, r *http.Request) {
	if supabaseClient == nil {
		http.Error(w, `{"error":"supabase no configurado"}`, http.StatusInternalServerError)
		return
	}
	res, _, err := supabaseClient.From("bet_fights").Select("*", "", false).Eq("status", "open").Execute()
	if err != nil {
		http.Error(w, `{"error":"error al leer peleas abiertas"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}

func myBetsHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := albumSessionFromRequest(r)
	if err != nil || claims == nil {
		http.Error(w, `{"error":"no autorizado"}`, http.StatusUnauthorized)
		return
	}
	if supabaseClient == nil {
		http.Error(w, `{"error":"supabase no configurado"}`, http.StatusInternalServerError)
		return
	}
	// Sort handled natively in Supabase query removing Order() so we avoid missing types
	res, _, err := supabaseClient.From("bets").Select("*", "", false).Eq("user_username", claims.Pseudonimo).Execute()
	if err != nil {
		http.Error(w, `{"error":"error al leer apuestas"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}

func placeBetHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := albumSessionFromRequest(r)
	if err != nil || claims == nil {
		http.Error(w, `{"error":"no autorizado"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		FightID       string `json:"fight_id"`
		Division      string `json:"division"`
		FighterA      string `json:"fighter_a"`
		FighterB      string `json:"fighter_b"`
		PickedPseudo  string `json:"picked_pseudo"`
		SobresAmount  int    `json:"sobres_amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"json inválido"}`, http.StatusBadRequest)
		return
	}

	if req.SobresAmount < 1 {
		http.Error(w, `{"error":"monto mínimo 1 sobre"}`, http.StatusBadRequest)
		return
	}

	var fights []BetFight
	resFight, _, err := supabaseClient.From("bet_fights").Select("*", "", false).Eq("fight_id", req.FightID).Execute()
	if err == nil {
		json.Unmarshal(resFight, &fights)
	}
	if len(fights) == 0 || fights[0].Status != "open" {
		http.Error(w, `{"error":"la pelea no existe o ya no acepta apuestas"}`, http.StatusBadRequest)
		return
	}

	identityKey, identityKeys := albumIdentityKeysFromClaims(claims)
	balance, _, err := loadAlbumUserPackBalanceForKeys(identityKeys)
	if err != nil || balance.BonusPacks < req.SobresAmount {
		http.Error(w, `{"error":"no tienes suficientes sobres"}`, http.StatusBadRequest)
		return
	}

	targetUserID := identityKey
	if targetUserID == "" {
		targetUserID = claims.AlbumUserID
	}

	for i := 0; i < req.SobresAmount; i++ {
		_, _, errDec := decrementAlbumBonusPack(targetUserID, identityKeys)
		if errDec != nil {
			http.Error(w, `{"error":"error al descontar sobres"}`, http.StatusInternalServerError)
			return
		}
	}

	opp := req.FighterA
	if req.PickedPseudo == req.FighterA {
		opp = req.FighterB
	}

	bet := map[string]interface{}{
		"user_username":   claims.Pseudonimo,
		"fight_id":        req.FightID,
		"division":        req.Division,
		"picked_pseudo":   req.PickedPseudo,
		"opponent_pseudo": opp,
		"sobres_amount":   req.SobresAmount,
		"multiplier":      4.0,
		"status":          "pending",
	}

	_, _, err = supabaseClient.From("bets").Insert(bet, false, "", "", "").Execute()
	if err != nil {
		http.Error(w, `{"error":"error al registrar apuesta"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}

// ==========================================
// ENDPOINTS ADMIN
// ==========================================

func adminBetFightsHandler(w http.ResponseWriter, r *http.Request) {
	res, _, err := supabaseClient.From("bet_fights").Select("*", "", false).Execute()
	if err != nil {
		http.Error(w, `{"error":"error db"}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}

func adminCreateBetFightHandler(w http.ResponseWriter, r *http.Request) {
	var req BetFight
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"json"}`, 400)
		return
	}
	req.Status = "open"
	_, _, err := supabaseClient.From("bet_fights").Insert(req, false, "", "", "").Execute()
	if err != nil {
		http.Error(w, `{"error":"error db"}`, 500)
		return
	}
	w.Write([]byte(`{"success":true}`))
}

func adminResolveBetFightHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FightID      string `json:"fight_id"`
		WinnerPseudo string `json:"winner_pseudo"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"json"}`, 400)
		return
	}

	_, _, err := supabaseClient.From("bet_fights").Update(map[string]interface{}{
		"status":        "resolved",
		"winner_pseudo": req.WinnerPseudo,
		"resolved_at":   time.Now(),
	}, "", "").Eq("fight_id", req.FightID).Execute()
	if err != nil {
		http.Error(w, `{"error":"error db"}`, 500)
		return
	}

	var bets []Bet
	res, _, err := supabaseClient.From("bets").Select("*", "", false).Eq("fight_id", req.FightID).Eq("status", "pending").Execute()
	if err == nil {
		json.Unmarshal(res, &bets)
	}

	for _, bet := range bets {
		if bet.PickedPseudo == req.WinnerPseudo {
			payout := int(float64(bet.SobresAmount) * bet.Multiplier)

			targetUserID := albumPseudoAlias(bet.UserUsername)
			if targetUserID == "" {
				targetUserID = bet.UserUsername
			}
			balance, _ := loadAlbumUserPackBalance(targetUserID)
			setAlbumUserPackBalance(targetUserID, balance.BonusPacks+payout)

			supabaseClient.From("bets").Update(map[string]interface{}{
				"status":      "won",
				"payout":      payout,
				"resolved_at": time.Now(),
			}, "", "").Eq("id", bet.ID).Execute()
		} else {
			supabaseClient.From("bets").Update(map[string]interface{}{
				"status":      "lost",
				"payout":      0,
				"resolved_at": time.Now(),
			}, "", "").Eq("id", bet.ID).Execute()
		}
	}
	w.Write([]byte(`{"success":true}`))
}

func adminBetsHandler(w http.ResponseWriter, r *http.Request) {
	res, _, err := supabaseClient.From("bets").Select("*", "", false).Execute()
	if err != nil {
		http.Error(w, `{"error":"error db"}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(res)
}

func adminBracketResultHandler(w http.ResponseWriter, r *http.Request) {
	var req BracketResult
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"json"}`, 400)
		return
	}
	_, _, err := supabaseClient.From("bracket_results").Insert(req, false, "", "", "").Execute()
	if err != nil {
		http.Error(w, `{"error":"error db"}`, 500)
		return
	}
	w.Write([]byte(`{"success":true}`))
}
