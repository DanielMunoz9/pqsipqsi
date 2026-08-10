const S='https://sxdckblvilraurcowvbb.supabase.co';
const K='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const headersPublic = { apikey: K, Authorization: 'Bearer ' + K };
const headersAlbum = { apikey: K, Authorization: 'Bearer ' + K, 'Accept-Profile': 'album', 'Content-Profile': 'album' };

async function syncAllUsersPacks() {
  const resRoster = await fetch(`${S}/rest/v1/v_current_roster?select=pseudonimo`, { headers: headersPublic });
  const roster = await resRoster.json();

  const resBals = await fetch(`${S}/rest/v1/user_pack_balances?select=user_id,bonus_packs`, { headers: headersAlbum });
  const bals = await resBals.json();
  const balsMap = new Map();
  bals.forEach(b => balsMap.set(b.user_id, b.bonus_packs));

  const updates = [];

  for (const r of roster) {
    const pseudo = r.pseudonimo.trim();
    const keyLower = 'pseudo:' + pseudo.toLowerCase();
    const keyExact = pseudo;

    let currentPacks = 0;
    let targetKey = keyLower;

    if (balsMap.has(keyLower)) {
      currentPacks = balsMap.get(keyLower);
      targetKey = keyLower;
    } else if (balsMap.has(keyExact)) {
      currentPacks = balsMap.get(keyExact);
      targetKey = keyExact;
    }

    updates.push({
      user_id: targetKey,
      bonus_packs: Math.max(currentPacks, 3)
    });
  }

  const resUpsert = await fetch(`${S}/rest/v1/user_pack_balances?on_conflict=user_id`, {
    method: 'POST',
    headers: { ...headersAlbum, 'Content-Type': 'application/json', 'Prefer': 'resolution=merge-duplicates,return=minimal' },
    body: JSON.stringify(updates)
  });

  if (!resUpsert.ok) {
    console.error("Error from Supabase:", await resUpsert.text());
  } else {
    console.log("Upsert success");
  }
}

syncAllUsersPacks();
