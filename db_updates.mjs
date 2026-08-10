import fs from 'fs';
const SUPABASE_URL = 'https://sxdckblvilraurcowvbb.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const headers = { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json', 'Prefer': 'return=minimal' };

async function go() {
  // 1. Close existing open fights
  console.log('Closing existing open fights...');
  const resClose = await fetch(`${SUPABASE_URL}/rest/v1/bet_fights?status=eq.open`, {
    method: 'PATCH',
    headers,
    body: JSON.stringify({ status: 'closed' })
  });
  console.log('Close fights status:', resClose.status);

  // 2. Insert new fights
  const uuidv4 = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  };
  
  const newFights = [
    { fight_id: uuidv4(), division: 'Universal', label: 'Pelea Estelar', fighter_a: 'Heather Yack', fighter_b: 'Thunder     ¡', status: 'open' },
    { fight_id: uuidv4(), division: 'Universal', label: 'Pelea Co-Estelar', fighter_a: 'Lucifer Der Vosgrönne', fighter_b: 'Sak', status: 'open' },
    { fight_id: uuidv4(), division: 'Universal', label: 'Pelea Oficial', fighter_a: '𝕽𝐲𝐮𝐮.', fighter_b: 'Fear.', status: 'open' },
    { fight_id: uuidv4(), division: 'Universal', label: 'Pelea Oficial', fighter_a: 'тєηкα', fighter_b: 'Dhaela', status: 'open' },
    { fight_id: uuidv4(), division: 'Universal', label: 'Pelea Oficial', fighter_a: '丂єρτιмυѕ ƒɢο', fighter_b: 'Musashi', status: 'open' },
    { fight_id: uuidv4(), division: 'Universal', label: 'Pelea Oficial', fighter_a: 'RagnaKurenai', fighter_b: 'Prox', status: 'open' },
    { fight_id: uuidv4(), division: 'Universal', label: 'Pelea Oficial', fighter_a: 'NeroAggelo', fighter_b: 'Setta Rojas (Cejotas)', status: 'open' },
    { fight_id: uuidv4(), division: 'Universal', label: 'Pelea Oficial', fighter_a: 'Artoria', fighter_b: 'Lucent', status: 'open' },
    { fight_id: uuidv4(), division: 'Universal', label: 'Pelea Oficial', fighter_a: 'GULTARD GABANNA', fighter_b: 'REVAN', status: 'open' }
  ];
  
  console.log('Inserting new fights...');
  const resInsert = await fetch(`${SUPABASE_URL}/rest/v1/bet_fights`, {
    method: 'POST',
    headers,
    body: JSON.stringify(newFights)
  });
  console.log('Insert fights status:', resInsert.status);

  // 3. Add 3 bonus_packs to everyone
  console.log('Fetching user_pack_balances...');
  const headersAlbum = { ...headers, 'Accept-Profile': 'album', 'Prefer': 'return=representation' };
  const resBals = await fetch(`${SUPABASE_URL}/rest/v1/user_pack_balances?select=*`, { headers: headersAlbum, method: 'GET' });
  const bals = await resBals.json();
  
  console.log(`Found ${bals.length} pack balances. Updating...`);
  
  // Bulk upsert to update
  const updatedBals = bals.map(b => ({
    ...b,
    bonus_packs: (b.bonus_packs || 0) + 3
  }));
  
  // Send in batches of 1000
  const headersUpsert = { ...headersAlbum, 'Content-Profile': 'album', 'Prefer': 'resolution=merge-duplicates' };
  const resUpsert = await fetch(`${SUPABASE_URL}/rest/v1/user_pack_balances`, {
    method: 'POST',
    headers: headersUpsert,
    body: JSON.stringify(updatedBals)
  });
  console.log('Upsert packs status:', resUpsert.status);
  
}
go();
