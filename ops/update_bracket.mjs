import fs from 'fs';

const SUPABASE_URL = "https://sxdckblvilraurcowvbb.supabase.co";
const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA";

const headers = {
  'apikey': SUPABASE_KEY,
  'Authorization': `Bearer ${SUPABASE_KEY}`,
  'Content-Type': 'application/json',
  'Prefer': 'return=minimal'
};

const rows = [
  { division: 'Ciudad', match_code: 'CL1', round: 1, winner_pseudo: 'Dktosh', loser_pseudo: 'GULTA' },
  { division: 'Ciudad', match_code: 'CL2', round: 1, winner_pseudo: 'Ohma', loser_pseudo: 'Fear.' },
  { division: 'Ciudad', match_code: 'CL3', round: 1, winner_pseudo: 'ARAKIEL', loser_pseudo: 'Justice' },
  { division: 'Ciudad', match_code: 'CL4', round: 1, winner_pseudo: 'Soujiro', loser_pseudo: 'Tenka' },
  { division: 'Ciudad', match_code: 'CR1', round: 1, winner_pseudo: 'Heather', loser_pseudo: 'Thunder' },
  { division: 'Ciudad', match_code: 'CR2', round: 1, winner_pseudo: 'Absylum', loser_pseudo: 'Ryuu.' },
  { division: 'Ciudad', match_code: 'CR3', round: 1, winner_pseudo: 'Evans', loser_pseudo: 'Musashi' },
  { division: 'Ciudad', match_code: 'CR4', round: 1, winner_pseudo: 'Baal', loser_pseudo: 'Dhaela' },
  { division: 'Universal', match_code: 'U1', round: 1, winner_pseudo: 'Khamzat The Borz Reaper', loser_pseudo: 'Sekiro' },
  { division: 'Universal', match_code: 'U2', round: 1, winner_pseudo: 'NEPHALEM', loser_pseudo: 'FuckU admin' },
  { division: 'Universal', match_code: 'U4', round: 1, winner_pseudo: 'JIM Merus Jr.', loser_pseudo: 'RagnaKurenai' },
  { division: 'Universal', match_code: 'U5', round: 1, winner_pseudo: 'Mel', loser_pseudo: 'Prox' }
];

async function run() {
  const url = `${SUPABASE_URL}/rest/v1/bracket_results`;
  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(rows)
  });
  console.log(res.status, res.statusText);
  if (!res.ok) {
    console.error(await res.text());
  }
}

run();
