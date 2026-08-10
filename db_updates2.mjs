import fs from 'fs';
const SUPABASE_URL = 'https://sxdckblvilraurcowvbb.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const headers = { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` };

async function go() {
  const headersAlbum = { ...headers, 'Accept-Profile': 'album', 'Prefer': 'return=minimal', 'Content-Type': 'application/json' };
  const resBals = await fetch(`${SUPABASE_URL}/rest/v1/user_pack_balances?select=id,bonus_packs`, { headers: { ...headers, 'Accept-Profile': 'album' }, method: 'GET' });
  const bals = await resBals.json();
  
  console.log(`Updating ${bals.length} balances...`);
  
  for (const b of bals) {
    await fetch(`${SUPABASE_URL}/rest/v1/user_pack_balances?id=eq.${b.id}`, {
      method: 'PATCH',
      headers: headersAlbum,
      body: JSON.stringify({ bonus_packs: (b.bonus_packs || 0) + 3 })
    });
  }
  
  console.log('Done updating balances.');
}
go();
