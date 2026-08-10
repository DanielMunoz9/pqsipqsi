const S='https://sxdckblvilraurcowvbb.supabase.co';
const K='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const headersAlbum = { apikey: K, Authorization: 'Bearer ' + K, 'Accept-Profile': 'album', 'Content-Profile': 'album', 'Content-Type': 'application/json' };

async function fixZeros() {
  const resBals = await fetch(`${S}/rest/v1/user_pack_balances?select=user_id,bonus_packs&bonus_packs=eq.0`, { headers: headersAlbum });
  const bals = await resBals.json();
  console.log(`Cuentas con 0 sobres: ${bals.length}`);
  
  if (bals.length > 0) {
    const updates = bals.map(b => ({ user_id: b.user_id, bonus_packs: 3 }));
    const resUpsert = await fetch(`${S}/rest/v1/user_pack_balances?on_conflict=user_id`, {
      method: 'POST',
      headers: { ...headersAlbum, 'Prefer': 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify(updates)
    });
    console.log("Upsert status:", resUpsert.status);
  }
}

fixZeros();
