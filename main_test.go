package main

import (
	"fmt"
	"testing"
)

func TestNormalizedPseudoMatchKey(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain ascii", input: "Baal", want: "baal"},
		{name: "styled unicode", input: "𝕭𝐚𝐚𝐥", want: "baal"},
		{name: "spaces and separators", input: " B-a_a l ", want: "baal"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizedPseudoMatchKey(tc.input)
			if got != tc.want {
				t.Fatalf("normalizedPseudoMatchKey(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSameNormalizedPseudo(t *testing.T) {
	if !sameNormalizedPseudo("Baal", "𝕭𝐚𝐚𝐥") {
		t.Fatal("expected Baal and styled Baal to match")
	}
	if sameNormalizedPseudo("Baal", "Bandet") {
		t.Fatal("did not expect unrelated pseudonyms to match")
	}
}

func TestOfficialQualifiedPlayersByDivisionDeduplicatesBeforeLimit(t *testing.T) {
	players := make([]PublicPlayer, 0, 17)
	for i := 1; i <= 16; i++ {
		players = append(players, PublicPlayer{
			Pseudonimo:      fmt.Sprintf("Player%02d", i),
			Division:        "Ciudad",
			Status:          "active",
			Timestamp:       fmt.Sprintf("2026-05-%02dT00:00:00Z", i),
			PlayerProfileID: fmt.Sprintf("profile-%02d", i),
		})
	}

	players = append(players, PublicPlayer{
		Pseudonimo:      "Player02",
		Division:        "Ciudad",
		Status:          "active",
		Timestamp:       "2026-05-02T00:00:00Z",
		PlayerProfileID: "profile-02",
	})

	grouped := officialQualifiedPlayersByDivision(players, 16)
	city := grouped["ciudad"]
	if len(city) != 16 {
		t.Fatalf("expected 16 unique official slots, got %d", len(city))
	}

	seen := make(map[string]struct{}, len(city))
	for _, player := range city {
		if _, exists := seen[player.Pseudonimo]; exists {
			t.Fatalf("duplicate competitor remained in official slots: %s", player.Pseudonimo)
		}
		seen[player.Pseudonimo] = struct{}{}
	}

	if _, exists := seen["Player16"]; !exists {
		t.Fatalf("expected last unique competitor to remain after deduplication, got %#v", city)
	}
	if _, exists := seen["Player02"]; !exists {
		t.Fatalf("expected duplicated competitor to remain once after deduplication")
	}
}

func TestOfficialQualifiedPlayersByDivisionKeepsBestSnapshot(t *testing.T) {
	players := []PublicPlayer{
		{
			Pseudonimo: "Abyssilum",
			Division:   "Ciudad",
			Status:     "active",
		},
		{
			Pseudonimo:      "Abyssilum",
			Division:        "Ciudad",
			Status:          "active",
			Timestamp:       "2026-05-10T14:00:00Z",
			AvatarURL:       "https://example.com/abyss.png",
			PlayerProfileID: "profile-abyss",
		},
	}

	grouped := officialQualifiedPlayersByDivision(players, 16)
	city := grouped["ciudad"]
	if len(city) != 1 {
		t.Fatalf("expected 1 merged competitor, got %d", len(city))
	}

	player := city[0]
	if player.Timestamp != "2026-05-10T14:00:00Z" {
		t.Fatalf("expected merged competitor to keep timestamp, got %q", player.Timestamp)
	}
	if player.AvatarURL != "https://example.com/abyss.png" {
		t.Fatalf("expected merged competitor to keep avatar, got %q", player.AvatarURL)
	}
	if player.PlayerProfileID != "profile-abyss" {
		t.Fatalf("expected merged competitor to keep profile id, got %q", player.PlayerProfileID)
	}
}

func TestOfficialQualifiedPlayersByDivisionUniversalCapIncludesReservedLastSlot(t *testing.T) {
	players := make([]PublicPlayer, 0, 11)
	for i := 1; i <= 11; i++ {
		players = append(players, PublicPlayer{
			Pseudonimo:      fmt.Sprintf("Universal%02d", i),
			Division:        "Universal",
			Status:          "active",
			Timestamp:       fmt.Sprintf("2026-05-%02dT00:00:00Z", i),
			PlayerProfileID: fmt.Sprintf("u-profile-%02d", i),
		})
	}

	grouped := officialQualifiedPlayersByDivision(players, 16)
	universal := grouped["universal"]
	if len(universal) != universalDivisionSlotCap {
		t.Fatalf("expected %d universal official slots, got %d", universalDivisionSlotCap, len(universal))
	}
	if universal[len(universal)-1].Pseudonimo != reservedUniversalPseudo {
		t.Fatalf("expected reserved universal closer %q as last slot, got %q", reservedUniversalPseudo, universal[len(universal)-1].Pseudonimo)
	}
}

func TestShouldFreezeOfficialUpgrade(t *testing.T) {
	tests := []struct {
		name                string
		status              string
		completedFightCount int
		scheduledFightCount int
		want                bool
	}{
		{
			name:                "active profile stays frozen",
			status:              "active",
			completedFightCount: 0,
			scheduledFightCount: 0,
			want:                true,
		},
		{
			name:                "written duel freezes slot",
			status:              "inactive",
			completedFightCount: 0,
			scheduledFightCount: 1,
			want:                true,
		},
		{
			name:                "recorded combat freezes slot",
			status:              "inactive",
			completedFightCount: 2,
			scheduledFightCount: 0,
			want:                true,
		},
		{
			name:                "first approval can still assign slot",
			status:              "inactive",
			completedFightCount: 0,
			scheduledFightCount: 0,
			want:                false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldFreezeOfficialUpgrade(tc.status, tc.completedFightCount, tc.scheduledFightCount)
			if got != tc.want {
				t.Fatalf("shouldFreezeOfficialUpgrade(%q, %d, %d) = %t, want %t", tc.status, tc.completedFightCount, tc.scheduledFightCount, got, tc.want)
			}
		})
	}
}

func TestIsSupabaseMissingTableError(t *testing.T) {
	err := fmt.Errorf(`{"code":"42P01","message":"relation \"public.match_history\" does not exist"}`)
	if !isSupabaseMissingTableError(err, "match_history") {
		t.Fatal("expected missing-table detector to recognize relation error")
	}

	err = fmt.Errorf(`{"code":"PGRST205","message":"Could not find the table 'public.match_history' in the schema cache"}`)
	if !isSupabaseMissingTableError(err, "match_history") {
		t.Fatal("expected missing-table detector to recognize schema-cache table error")
	}

	err = fmt.Errorf(`timeout contacting supabase`)
	if isSupabaseMissingTableError(err, "match_history") {
		t.Fatal("did not expect generic network error to look like missing table")
	}
}

func TestIsSupabaseMissingColumnError(t *testing.T) {
	err := fmt.Errorf(`{"code":"PGRST204","message":"Could not find the 'player1_char' column of 'match_history' in the schema cache"}`)
	if !isSupabaseMissingColumnError(err) {
		t.Fatal("expected missing-column detector to recognize schema-cache column error")
	}

	err = fmt.Errorf(`pq: column division does not exist`)
	if !isSupabaseMissingColumnError(err) {
		t.Fatal("expected missing-column detector to recognize SQL column error")
	}

	err = fmt.Errorf(`context deadline exceeded`)
	if isSupabaseMissingColumnError(err) {
		t.Fatal("did not expect timeout to look like missing column")
	}
}

func TestNextMatchHistoryInsertPayloadDropsMatchedOptionalGroup(t *testing.T) {
	payload := map[string]interface{}{
		"event_name":     "Bellator",
		"event_date":     "2026-05-26",
		"player1_pseudo": "A",
		"player2_pseudo": "B",
		"player1_avatar": "https://example.com/a.png",
		"player2_avatar": "https://example.com/b.png",
		"result":         "player1",
		"player1_char":   "Naruto",
		"player2_char":   "Sasuke",
		"division":       "Ciudad",
		"notes":          "final",
	}

	next := nextMatchHistoryInsertPayload(payload, fmt.Errorf(`{"message":"Could not find the 'player1_char' column of 'match_history' in the schema cache"}`))
	if next == nil {
		t.Fatal("expected fallback payload after missing column error")
	}
	if _, exists := next["player1_char"]; exists {
		t.Fatal("expected player1_char to be removed")
	}
	if _, exists := next["player2_char"]; exists {
		t.Fatal("expected player2_char to be removed together with player1_char")
	}
	if _, exists := next["player1_avatar"]; !exists {
		t.Fatal("expected unrelated optional columns to remain")
	}
	if _, exists := next["division"]; !exists {
		t.Fatal("expected division to remain")
	}
}

func TestNextMatchHistoryInsertPayloadDropsAllOptionalFieldsOnGenericColumnError(t *testing.T) {
	payload := map[string]interface{}{
		"event_name":     "Bellator",
		"event_date":     "2026-05-26",
		"player1_pseudo": "A",
		"player2_pseudo": "B",
		"player1_avatar": "https://example.com/a.png",
		"player2_avatar": "https://example.com/b.png",
		"result":         "player1",
		"player1_char":   "Naruto",
		"player2_char":   "Sasuke",
		"division":       "Ciudad",
		"notes":          "final",
	}

	next := nextMatchHistoryInsertPayload(payload, fmt.Errorf(`pq: column legacy_extra does not exist`))
	if next == nil {
		t.Fatal("expected generic missing-column error to trigger fallback payload")
	}
	for _, field := range []string{"player1_avatar", "player2_avatar", "player1_char", "player2_char", "division", "notes"} {
		if _, exists := next[field]; exists {
			t.Fatalf("expected optional field %s to be removed", field)
		}
	}
	for _, field := range []string{"event_name", "event_date", "player1_pseudo", "player2_pseudo", "result"} {
		if _, exists := next[field]; !exists {
			t.Fatalf("expected required field %s to remain", field)
		}
	}
}

func TestCompletedFightNotesRoundTrip(t *testing.T) {
	encoded := encodeCompletedFightNotes("player2", "Gojo", "Sukuna", "Victoria por control total")
	meta, ok := decodeCompletedFightNotes(encoded)
	if !ok {
		t.Fatal("expected encoded completed-fight note to decode")
	}
	if meta.State != "completed" {
		t.Fatalf("expected completed state, got %q", meta.State)
	}
	if meta.Result != "player2" {
		t.Fatalf("expected player2 result, got %q", meta.Result)
	}
	if meta.Player1Char != "Gojo" || meta.Player2Char != "Sukuna" {
		t.Fatalf("expected stored character names, got %#v", meta)
	}
	if meta.Notes != "Victoria por control total" {
		t.Fatalf("expected stored note, got %q", meta.Notes)
	}
}

func TestMatchRecordFromUpcomingFightRowUsesEncodedNotes(t *testing.T) {
	row := map[string]interface{}{
		"id":             "68a7a850-888a-4a8f-aa11-d98ec5201629",
		"event_name":     "Bellator Ciudad",
		"event_date":     "2026-05-27",
		"player1_pseudo": "Alpha",
		"player2_pseudo": "Beta",
		"player1_avatar": "https://example.com/a.png",
		"player2_avatar": "https://example.com/b.png",
		"division":       "Ciudad",
		"notes":          encodeCompletedFightNotes("player1", "Itachi", "Madara", "Main event"),
	}

	rec, ok := matchRecordFromUpcomingFightRow(row)
	if !ok {
		t.Fatal("expected upcoming_fights row with encoded notes to become match record")
	}
	if rec.ID != "68a7a850-888a-4a8f-aa11-d98ec5201629" {
		t.Fatalf("expected UUID-backed record id, got %q", rec.ID)
	}
	if rec.Result != "player1" {
		t.Fatalf("expected player1 result, got %q", rec.Result)
	}
	if rec.Player1Char != "Itachi" || rec.Player2Char != "Madara" {
		t.Fatalf("expected characters from encoded notes, got %#v", rec)
	}
	if rec.Notes != "Main event" {
		t.Fatalf("expected decoded notes, got %q", rec.Notes)
	}
	if rec.EventDateFmt != "27 May 2026" {
		t.Fatalf("expected formatted date, got %q", rec.EventDateFmt)
	}
}

func TestMatchRecordIDNormalizesNumericAndUUIDValues(t *testing.T) {
	if got := matchRecordID(float64(99)); got != "99" {
		t.Fatalf("expected numeric id to normalize to 99, got %q", got)
	}
	if got := matchRecordID("68a7a850-888a-4a8f-aa11-d98ec5201629"); got != "68a7a850-888a-4a8f-aa11-d98ec5201629" {
		t.Fatalf("expected UUID id to remain intact, got %q", got)
	}
}

func TestBuildReverseFightStatUpdatesForPlayer2Win(t *testing.T) {
	snap1 := PlayerSnapshot{Wins: 0, Losses: 3, Draws: 0, Streak: -3}
	snap2 := PlayerSnapshot{Wins: 4, Losses: 0, Draws: 0, Streak: 4}

	updates1, updates2 := buildReverseFightStatUpdates("player2", snap1, snap2)
	if got := updates1["losses"]; got != 2 {
		t.Fatalf("expected player1 losses to decrement to 2, got %#v", got)
	}
	if got := updates1["current_streak"]; got != -2 {
		t.Fatalf("expected player1 streak to move toward zero, got %#v", got)
	}
	if got := updates2["wins"]; got != 3 {
		t.Fatalf("expected player2 wins to decrement to 3, got %#v", got)
	}
	if got := updates2["current_streak"]; got != 3 {
		t.Fatalf("expected player2 streak to decrement to 3, got %#v", got)
	}
}

func TestBuildReverseFightStatUpdatesForDraw(t *testing.T) {
	snap1 := PlayerSnapshot{Wins: 1, Losses: 1, Draws: 2, Streak: 0}
	snap2 := PlayerSnapshot{Wins: 2, Losses: 0, Draws: 2, Streak: 0}

	updates1, updates2 := buildReverseFightStatUpdates("draw", snap1, snap2)
	if got := updates1["draws"]; got != 1 {
		t.Fatalf("expected player1 draws to decrement to 1, got %#v", got)
	}
	if got := updates2["draws"]; got != 1 {
		t.Fatalf("expected player2 draws to decrement to 1, got %#v", got)
	}
	if got := updates1["current_streak"]; got != 0 {
		t.Fatalf("expected draw deletion to keep streak reset, got %#v", got)
	}
}

func TestApplyRankingPointsOperation(t *testing.T) {
	tests := []struct {
		name      string
		current   int
		operation string
		amount    int
		wantNext  int
		wantDelta int
		wantErr   string
	}{
		{name: "add points", current: 12, operation: "add", amount: 8, wantNext: 20, wantDelta: 8},
		{name: "subtract points", current: 12, operation: "subtract", amount: 5, wantNext: 7, wantDelta: -5},
		{name: "subtract clamps at zero", current: 4, operation: "subtract", amount: 9, wantNext: 0, wantDelta: -4},
		{name: "set points", current: 12, operation: "set", amount: 30, wantNext: 30, wantDelta: 18},
		{name: "reject invalid amount", current: 12, operation: "add", amount: 0, wantErr: "cantidad_invalida"},
		{name: "reject invalid operation", current: 12, operation: "multiply", amount: 3, wantErr: "operacion_invalida"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next, delta, err := applyRankingPointsOperation(tc.current, tc.operation, tc.amount)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if next != tc.wantNext {
				t.Fatalf("expected next points %d, got %d", tc.wantNext, next)
			}
			if delta != tc.wantDelta {
				t.Fatalf("expected delta %d, got %d", tc.wantDelta, delta)
			}
		})
	}
}

func TestIsCompletedFightRowRejectsPlainScheduledNotes(t *testing.T) {
	if isCompletedFightRow("Traer roster confirmado") {
		t.Fatal("expected plain upcoming fight note to remain scheduled")
	}
}
