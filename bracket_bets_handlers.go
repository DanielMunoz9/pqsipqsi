package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	// "strings"
	"time"

	"github.com/gorilla/mux"
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
	res, _, err := supabaseClient.From("upcoming_fights").Select("*", "", false).Execute()
	if err != nil {
		http.Error(w, `{"error":"error al leer peleas abiertas"}`, http.StatusInternalServerError)
		return
	}
	if len(res) == 0 || string(res) == "null" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	var peleas []map[string]interface{}
	if err := json.Unmarshal(res, &peleas); err != nil {
		http.Error(w, `{"error":"error al decodificar peleas"}`, http.StatusInternalServerError)
		return
	}
	bets := make([]BetFight, 0)
	for _, p := range peleas {
		id, _ := p["id"].(string)
		p1, _ := p["player1_pseudo"].(string)
		p2, _ := p["player2_pseudo"].(string)
		div, _ := p["division"].(string)
		event, _ := p["event_name"].(string)

		// if !strings.Contains(strings.ToUpper(div), "FASE II") && !strings.Contains(strings.ToUpper(event), "FASE II") {
		// 	continue
		// }

		statusStr := "open"
		if strings.Contains(strings.ToUpper(event), "FASE II") {
			statusStr = "closed"
		}
		bets = append(bets, BetFight{
			ID:       id,
			FightID:  id,
			Division: div,
			Label:    event,
			FighterA: p1,
			FighterB: p2,
			Status:   statusStr,
		})
	}
	out, _ := json.Marshal(bets)
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func getBetFightDetailsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fightID := vars["id"]
	
	res, _, err := supabaseClient.From("bets").Select("user_username, picked_pseudo, opponent_pseudo, sobres_amount", "", false).Eq("fight_id", fightID).Execute()
	if err != nil {
		http.Error(w, `{"error":"error al obtener detalles"}`, http.StatusInternalServerError)
		return
	}
	
	var bets []map[string]interface{}
	json.Unmarshal(res, &bets)
	
	type BetDetail struct {
		Username string `json:"username"`
		Picked   string `json:"picked"`
		Sobres   int    `json:"sobres"`
	}
	
	var details []BetDetail
	var totalA, totalB int
	var fighterA, fighterB string
	
	for _, b := range bets {
		user, _ := b["user_username"].(string)
		picked, _ := b["picked_pseudo"].(string)
		opp, _ := b["opponent_pseudo"].(string)
		amtFloat, _ := b["sobres_amount"].(float64)
		amt := int(amtFloat)
		
		details = append(details, BetDetail{Username: user, Picked: picked, Sobres: amt})
		
		if fighterA == "" { fighterA = picked; fighterB = opp }
		
		if picked == fighterA {
			totalA += amt
		} else {
			totalB += amt
		}
	}
	
	// Añadir 5 sobres semilla a cada lado para cuota dinámica
	totalA += 5
	totalB += 5
	
	pctA := 50.0
	pctB := 50.0
	var oddsA, oddsB float64
	if totalA + totalB > 0 {
		pctA = math.Round(float64(totalA) / float64(totalA+totalB) * 100)
		pctB = 100.0 - pctA
		oddsA = math.Round((float64(totalA+totalB)/float64(totalA))*100)/100
		oddsB = math.Round((float64(totalA+totalB)/float64(totalB))*100)/100
	}
	
	resp := map[string]interface{}{
		"fighter_a": fighterA,
		"fighter_b": fighterB,
		"pct_a": pctA,
		"pct_b": pctB,
		"odds_a": oddsA,
		"odds_b": oddsB,
		"total_a": totalA - 5,
		"total_b": totalB - 5,
		"bets": details,
	}
	
	out, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
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
		FightID      string `json:"fight_id"`
		Division     string `json:"division"`
		FighterA     string `json:"fighter_a"`
		FighterB     string `json:"fighter_b"`
		PickedPseudo string `json:"picked_pseudo"`
		SobresAmount int    `json:"sobres_amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"json inválido"}`, http.StatusBadRequest)
		return
	}

	if req.SobresAmount < 1 {
		http.Error(w, `{"error":"monto mínimo 1 sobre"}`, http.StatusBadRequest)
		return
	}

	var peleas []map[string]interface{}
	resFight, _, err := supabaseClient.From("upcoming_fights").Select("*", "", false).Eq("id", req.FightID).Execute()
	if err == nil {
		json.Unmarshal(resFight, &peleas)
	}
	if len(peleas) == 0 {
		http.Error(w, `{"error":"la pelea no existe o ya no acepta apuestas"}`, http.StatusBadRequest)
		return
	}

	// Verificar fecha límite (10 de agosto 2026 00:00 hora local -> 05:00 UTC)
	deadline, _ := time.Parse(time.RFC3339, "2026-08-10T05:00:00Z")
	if time.Now().After(deadline) {
		http.Error(w, `{"error":"El plazo para apostar ya cerró (10 de Agosto)."}`, http.StatusBadRequest)
		return
	}

	// Verificar límite histórico de 5 sobres para esta pelea por este jugador
	var existingBets []map[string]interface{}
	supabaseClient.From("bets").Select("sobres_amount", "", false).
		Eq("fight_id", req.FightID).
		Eq("user_username", claims.Pseudonimo).
		ExecuteTo(&existingBets)
	
	totalApostado := 0
	for _, b := range existingBets {
		if amt, ok := b["sobres_amount"].(float64); ok {
			totalApostado += int(amt)
		}
	}

	if totalApostado+req.SobresAmount > 5 {
		http.Error(w, fmt.Sprintf(`{"error":"Límite de 5 sobres por pelea. Ya has apostado %d."}`, totalApostado), http.StatusBadRequest)
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
			log.Printf("Error descontando sobre: %v", errDec)
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

	// Satisfy the FK constraint on bets table by ensuring it exists in bet_fights
	supabaseClient.From("bet_fights").Insert(map[string]interface{}{
		"fight_id": req.FightID,
		"division": req.Division,
		"label": req.FighterA + " vs " + req.FighterB,
		"fighter_a": req.FighterA,
		"fighter_b": req.FighterB,
		"status": "open",
	}, false, "", "", "").Execute()

	_, _, err = supabaseClient.From("bets").Insert(bet, false, "", "", "").Execute()
	if err != nil {
		log.Printf("Error insertando apuesta db: %v", err)
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

func resolveBetsForMatch(p1, p2, winner string) {
	var bets []Bet
	res, _, err := supabaseClient.From("bets").Select("*", "", false).Eq("status", "pending").Execute()
	if err != nil { return }
	json.Unmarshal(res, &bets)
	
	var matchBets []Bet
	poolP1 := 5 // Base seed packs
	poolP2 := 5 // Base seed packs
	
	for _, bet := range bets {
		if (bet.PickedPseudo == p1 && bet.OpponentPseudo == p2) || (bet.PickedPseudo == p2 && bet.OpponentPseudo == p1) {
			matchBets = append(matchBets, bet)
			if bet.PickedPseudo == p1 {
				poolP1 += bet.SobresAmount
			} else {
				poolP2 += bet.SobresAmount
			}
		}
	}
	
	if len(matchBets) == 0 { return }
	
	totalPool := float64(poolP1 + poolP2)
	winningPool := float64(poolP1)
	if winner == p2 {
		winningPool = float64(poolP2)
	}
	
	odds := 1.0
	if winningPool > 0 {
		odds = totalPool / winningPool
	}
	
	for _, bet := range matchBets {
		if bet.PickedPseudo == winner {
			payout := int(math.Round(float64(bet.SobresAmount) * odds))
			targetUserID := albumPseudoAlias(bet.UserUsername)
			if targetUserID == "" { targetUserID = bet.UserUsername }
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

// ==========================================
// ESTADÍSTICAS DEL MERCADO (PÚBLICAS)
// ==========================================

type BetStats struct {
	TrendingFighters []TrendingFighter        `json:"trending_fighters"`
	FightStats       map[string]FightBetStats `json:"fight_stats"`
}

type TrendingFighter struct {
	Pseudo      string `json:"pseudo"`
	TotalSobres int    `json:"total_sobres"`
	BetsCount   int    `json:"bets_count"`
}

type FightBetStats struct {
	TotalA   int      `json:"total_a"`
	TotalB   int      `json:"total_b"`
	FighterA string   `json:"fighter_a"`
	FighterB string   `json:"fighter_b"`
	BetsA    []BetDet `json:"bets_a"`
	BetsB    []BetDet `json:"bets_b"`
	PctA     float64  `json:"pct_a"`
	PctB     float64  `json:"pct_b"`
	OddsA    float64  `json:"odds_a"`
	OddsB    float64  `json:"odds_b"`
}

type BetDet struct {
	Username string `json:"username"`
	Sobres   int    `json:"sobres"`
}

func getBetsStatsHandler(w http.ResponseWriter, r *http.Request) {
	var openFights []BetFight
	resFights, _, err := supabaseClient.From("upcoming_fights").Select("*", "", false).Execute()
	if err == nil {
		var peleas []map[string]interface{}
		json.Unmarshal(resFights, &peleas)
		for _, p := range peleas {
			id, _ := p["id"].(string)
			p1, _ := p["player1_pseudo"].(string)
			p2, _ := p["player2_pseudo"].(string)
			div, _ := p["division"].(string)
			_, _ = p["event_name"].(string)
			// if !strings.Contains(strings.ToUpper(div), "FASE II") && !strings.Contains(strings.ToUpper(event), "FASE II") {
			// 	continue
			// }
			statusStr := "open"
			if strings.Contains(strings.ToUpper(event), "FASE II") {
				statusStr = "closed"
			}
			openFights = append(openFights, BetFight{
				ID:       id,
				FightID:  id,
				Division: div,
				FighterA: p1,
				FighterB: p2,
				Status:   statusStr,
			})
		}
	}

	var allBets []Bet
	// Traer apuestas pendientes para las peleas abiertas, y también apuestas pasadas si queremos tendencias globales
	resBets, _, err := supabaseClient.From("bets").Select("*", "", false).Execute()
	if err == nil {
		json.Unmarshal(resBets, &allBets)
	}

	// 1. Trending
	trendingMap := make(map[string]*TrendingFighter)
	for _, b := range allBets {
		if _, exists := trendingMap[b.PickedPseudo]; !exists {
			trendingMap[b.PickedPseudo] = &TrendingFighter{Pseudo: b.PickedPseudo, TotalSobres: 0, BetsCount: 0}
		}
		trendingMap[b.PickedPseudo].TotalSobres += b.SobresAmount
		trendingMap[b.PickedPseudo].BetsCount++
	}

	var trendingList []TrendingFighter
	for _, tf := range trendingMap {
		trendingList = append(trendingList, *tf)
	}
	// Sort by total sobres desc
	for i := 0; i < len(trendingList); i++ {
		for j := i + 1; j < len(trendingList); j++ {
			if trendingList[j].TotalSobres > trendingList[i].TotalSobres {
				trendingList[i], trendingList[j] = trendingList[j], trendingList[i]
			}
		}
	}
	if len(trendingList) > 10 {
		trendingList = trendingList[:10]
	}
	if trendingList == nil {
		trendingList = []TrendingFighter{}
	}

	// 2. Fight Stats
	fightStats := make(map[string]FightBetStats)
	for _, f := range openFights {
		fs := FightBetStats{
			TotalA:   0,
			TotalB:   0,
			FighterA: f.FighterA,
			FighterB: f.FighterB,
			BetsA:    []BetDet{},
			BetsB:    []BetDet{},
		}
		// find bets for this fight
		for _, b := range allBets {
			if b.FightID == f.FightID {
				if b.PickedPseudo == f.FighterA {
					fs.TotalA += b.SobresAmount
					fs.BetsA = append(fs.BetsA, BetDet{Username: b.UserUsername, Sobres: b.SobresAmount})
				} else if b.PickedPseudo == f.FighterB {
					fs.TotalB += b.SobresAmount
					fs.BetsB = append(fs.BetsB, BetDet{Username: b.UserUsername, Sobres: b.SobresAmount})
				}
			}
		}
		
		// Pari-Mutuel Calculation with 5 seed packs
		poolA := float64(fs.TotalA + 5)
		poolB := float64(fs.TotalB + 5)
		totalPool := poolA + poolB
		
		fs.PctA = math.Round((poolA / totalPool) * 100)
		fs.PctB = 100.0 - fs.PctA
		fs.OddsA = math.Round((totalPool / poolA) * 100) / 100
		fs.OddsB = math.Round((totalPool / poolB) * 100) / 100
		
		fightStats[f.FightID] = fs
	}

	out := BetStats{
		TrendingFighters: trendingList,
		FightStats:       fightStats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}



