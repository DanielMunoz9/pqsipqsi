const SUPABASE_URL = 'https://sxdckblvilraurcowvbb.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const headers = { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Accept-Profile': 'album' };

async function check() {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/user_pack_balances?select=user_id,bonus_packs&order=bonus_packs.desc`, { headers });
  const data = await res.json();
  console.log(`Total cuentas: ${data.length}`);
  console.log(`Con 0 sobres: ${data.filter(d => d.bonus_packs === 0).length}`);
  console.log(`Con 3+ sobres: ${data.filter(d => d.bonus_packs >= 3).length}`);
  console.log('\n--- Detalle ---');
  data.forEach(d => console.log(`  ${d.user_id.padEnd(30)} → ${d.bonus_packs} sobres`));
}
check();
