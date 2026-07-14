package main

import "testing"

func TestResolveAlbumTradeIncrementUserIDFallsBackToNonPseudoAlias(t *testing.T) {
	preferredUserID := "pseudo:baal"
	identityKeys := []string{"pseudo:baal", "hw-baal"}

	originalAlbumClient := albumSupabaseClient
	t.Cleanup(func() {
		albumSupabaseClient = originalAlbumClient
	})
	albumSupabaseClient = nil

	got := resolveAlbumTradeIncrementUserID(preferredUserID, identityKeys)
	if got != "hw-baal" {
		t.Fatalf("resolveAlbumTradeIncrementUserID() without db rows = %q, want %q", got, "hw-baal")
	}
}

func TestResolveAlbumTradeIncrementUserIDKeepsExplicitNonPseudoIdentity(t *testing.T) {
	preferredUserID := "hw-requester"
	identityKeys := []string{"hw-requester", "pseudo:requester"}

	originalAlbumClient := albumSupabaseClient
	t.Cleanup(func() {
		albumSupabaseClient = originalAlbumClient
	})
	albumSupabaseClient = nil

	got := resolveAlbumTradeIncrementUserID(preferredUserID, identityKeys)
	if got != preferredUserID {
		t.Fatalf("resolveAlbumTradeIncrementUserID() = %q, want %q", got, preferredUserID)
	}
}

func TestUpsertAlbumKnownUserKeepsOperationalExcludedPseudo(t *testing.T) {
	seenByUserID := map[string]int{}
	seenByPseudo := map[string]int{}

	users := upsertAlbumKnownUser(nil, seenByUserID, seenByPseudo, "hw-windham", "Windham")
	if len(users) != 1 {
		t.Fatalf("upsertAlbumKnownUser() len = %d, want 1", len(users))
	}
	if users[0].Pseudonimo != "Windham" {
		t.Fatalf("upsertAlbumKnownUser() pseudonimo = %q, want %q", users[0].Pseudonimo, "Windham")
	}
	if users[0].UserID != "hw-windham" {
		t.Fatalf("upsertAlbumKnownUser() userID = %q, want %q", users[0].UserID, "hw-windham")
	}
}

func TestSanitizeAlbumTradeRequestsKeepsOperationalExcludedPseudos(t *testing.T) {
	requests := []albumTradeRequest{{
		ID:           "trade-1",
		IdentityKey:  "hw-windham",
		Player:       "Windham",
		CreatedAt:    "2026-07-03T00:00:00Z",
		Status:       "open",
		TargetUserID: "hw-ridley",
		TargetPlayer: "Jhon Ridley",
		Offer:        []albumTradeStickerItem{{ID: "s1", Name: "Windham #1"}},
		Want:         []albumTradeStickerItem{{ID: "s2", Name: "Ridley #2"}},
	}}

	clean := sanitizeAlbumTradeRequests(requests)
	if len(clean) != 1 {
		t.Fatalf("sanitizeAlbumTradeRequests() len = %d, want 1", len(clean))
	}
	if clean[0].Player != "Windham" {
		t.Fatalf("sanitizeAlbumTradeRequests() player = %q, want %q", clean[0].Player, "Windham")
	}
	if clean[0].TargetPlayer != "Jhon Ridley" {
		t.Fatalf("sanitizeAlbumTradeRequests() target = %q, want %q", clean[0].TargetPlayer, "Jhon Ridley")
	}
}

func TestAlbumCatalogPoolKeyUsesSpecialTypeOverRarity(t *testing.T) {
	cases := []struct {
		name     string
		row      map[string]interface{}
		wantPool string
	}{
		{name: "iconico", row: map[string]interface{}{"rarity": "legendario", "variant": "normal", "special_type": "iconico"}, wantPool: "iconico"},
		{name: "extra", row: map[string]interface{}{"rarity": "legendario", "variant": "normal", "special_type": "extra"}, wantPool: "extra"},
		{name: "diamante", row: map[string]interface{}{"rarity": "legendario", "variant": "normal", "special_type": "diamante"}, wantPool: "diamante"},
		{name: "gold", row: map[string]interface{}{"rarity": "legendario", "variant": "dorado", "special_type": "normal"}, wantPool: "legendario_dorado"},
		{name: "normalRarity", row: map[string]interface{}{"rarity": "epico", "variant": "normal", "special_type": "normal"}, wantPool: "epico"},
	}

	for _, tc := range cases {
		if got := albumCatalogPoolKeyForRow(tc.row); got != tc.wantPool {
			t.Fatalf("albumCatalogPoolKeyForRow(%s) = %q, want %q", tc.name, got, tc.wantPool)
		}
	}
}

func TestAlbumSpecialDropDistributionBoostsIconicosYDiamantes(t *testing.T) {
	dist := albumSpecialDropDistribution()
	weights := map[string]int{}
	for _, item := range dist {
		weights[item.rarity] = item.weight
	}
	if weights["iconico"] <= 0 || weights["diamante"] <= 0 {
		t.Fatalf("albumSpecialDropDistribution() should include iconico and diamante weights, got %#v", weights)
	}
	if weights["legendario_dorado"] <= weights["iconico"] {
		t.Fatalf("legendario_dorado should not dominate special drops, got %#v", weights)
	}
	if weights["diamante"] < 2 {
		t.Fatalf("diamante should be more common than a single-slot drop, got %#v", weights)
	}
}
