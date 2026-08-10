import fs from 'fs';
const SUPABASE_URL = 'https://sxdckblvilraurcowvbb.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const headers = { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json' };

async function go() {
  // Fetch roster to get avatars
  const resRoster = await fetch(`${SUPABASE_URL}/rest/v1/v_current_roster?select=pseudonimo,avatar_url`, { headers });
  const roster = await resRoster.json();
  const avatarMap = {};
  for (const r of roster) {
    avatarMap[r.pseudonimo] = r.avatar_url;
  }

  const newFights = [
    { player1_pseudo: 'Heather Yack', player2_pseudo: 'Thunder     ¡', event_name: 'Pelea Estelar', division: 'Universal', event_date: '2026-08-10' },
    { player1_pseudo: 'Lucifer Der Vosgrönne', player2_pseudo: 'Sak', event_name: 'Pelea Co-Estelar', division: 'Universal', event_date: '2026-08-10' },
    { player1_pseudo: '𝕽𝐲𝐮𝐮.', player2_pseudo: 'Fear.', event_name: 'Pelea Oficial', division: 'Universal', event_date: '2026-08-10' },
    { player1_pseudo: 'тєηкα', player2_pseudo: 'Dhaela', event_name: 'Pelea Oficial', division: 'Universal', event_date: '2026-08-10' },
    { player1_pseudo: '丂єρτιмυѕ ƒɢο', player2_pseudo: 'Musashi', event_name: 'Pelea Oficial', division: 'Universal', event_date: '2026-08-10' },
    { player1_pseudo: 'RagnaKurenai', player2_pseudo: 'Morwen', event_name: 'Pelea Oficial', division: 'Universal', event_date: '2026-08-10' },
    { player1_pseudo: 'NeroAggelo', player2_pseudo: 'Setta Rojas (Cejotas)', event_name: 'Pelea Oficial', division: 'Universal', event_date: '2026-08-10' },
    { player1_pseudo: 'Artoria', player2_pseudo: 'Lucent', event_name: 'Pelea Oficial', division: 'Universal', event_date: '2026-08-10' },
    { player1_pseudo: 'GULTARD GABANNA', player2_pseudo: 'REVAN', event_name: 'Pelea Oficial', division: 'Universal', event_date: '2026-08-10' }
  ];

  for (let f of newFights) {
    f.player1_avatar = avatarMap[f.player1_pseudo] || '';
    f.player2_avatar = avatarMap[f.player2_pseudo] || '';
  }

  const resInsert = await fetch(`${SUPABASE_URL}/rest/v1/upcoming_fights`, {
    method: 'POST',
    headers: { ...headers, 'Prefer': 'return=minimal' },
    body: JSON.stringify(newFights)
  });
  console.log('Inserted upcoming_fights status:', resInsert.status);
}
go();
