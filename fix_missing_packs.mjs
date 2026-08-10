const SUPABASE_URL = 'https://sxdckblvilraurcowvbb.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const h = { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Accept-Profile': 'album', 'Content-Type': 'application/json' };

async function go() {
  // 1. Get ALL album users (the actual registered accounts)
  const resUsers = await fetch(`${SUPABASE_URL}/rest/v1/album_sessions?select=user_id,pseudonimo`, { headers: h });
  const users = await resUsers.json();
  console.log(`Total album_sessions (cuentas): ${users.length}`);

  // 2. Get existing pack balances
  const resBals = await fetch(`${SUPABASE_URL}/rest/v1/user_pack_balances?select=user_id`, { headers: h });
  const bals = await resBals.json();
  const existingIds = new Set(bals.map(b => b.user_id));
  console.log(`Cuentas CON pack balance: ${existingIds.size}`);

  // 3. Find users WITHOUT a pack balance row
  const missing = users.filter(u => !existingIds.has(u.user_id));
  console.log(`Cuentas SIN pack balance (faltantes): ${missing.length}`);
  
  if (missing.length === 0) {
    console.log('No hay faltantes!');
    return;
  }

  // 4. Create pack balance rows with 3 bonus_packs for each missing user
  const newRows = missing.map(u => ({
    user_id: u.user_id,
    bonus_packs: 3
  }));

  // Insert in batches of 50
  for (let i = 0; i < newRows.length; i += 50) {
    const batch = newRows.slice(i, i + 50);
    const res = await fetch(`${SUPABASE_URL}/rest/v1/user_pack_balances`, {
      method: 'POST',
      headers: { ...h, 'Content-Profile': 'album', 'Prefer': 'return=minimal,resolution=merge-duplicates' },
      body: JSON.stringify(batch)
    });
    console.log(`Batch ${Math.floor(i/50)+1}: status ${res.status} (${batch.length} rows)`);
    if (!res.ok) {
      console.error(await res.text());
    }
  }

  // 5. Verify final count
  const resVerify = await fetch(`${SUPABASE_URL}/rest/v1/user_pack_balances?select=user_id,bonus_packs`, { headers: h });
  const final = await resVerify.json();
  console.log(`\nTotal cuentas con pack balance ahora: ${final.length}`);
  console.log(`Con 3+ sobres: ${final.filter(f => f.bonus_packs >= 3).length}`);
  console.log(`Con 0 sobres: ${final.filter(f => f.bonus_packs === 0).length}`);
}
go();
