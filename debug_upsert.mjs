import fs from 'fs';
const SUPABASE_URL = 'https://sxdckblvilraurcowvbb.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const headersAlbum = { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json', 'Accept-Profile': 'album', 'Content-Profile': 'album', 'Prefer': 'resolution=merge-duplicates' };

async function go() {
  const resBals = await fetch(`${SUPABASE_URL}/rest/v1/user_pack_balances?select=id,bonus_packs`, { headers: { ...headersAlbum, 'Prefer': 'return=representation' }, method: 'GET' });
  const bals = await resBals.json();
  const updatedBals = bals.map(b => ({ id: b.id, bonus_packs: (b.bonus_packs || 0) + 3 }));
  const resUpsert = await fetch(`${SUPABASE_URL}/rest/v1/user_pack_balances`, { method: 'POST', headers: headersAlbum, body: JSON.stringify(updatedBals) });
  console.log('Status:', resUpsert.status);
  console.log('Body:', await resUpsert.text());
}
go();
