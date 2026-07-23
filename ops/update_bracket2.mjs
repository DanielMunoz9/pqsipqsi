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
  { division: 'Universal', match_code: 'U3', round: 1, winner_pseudo: 'Inverse Bernkastel', loser_pseudo: 'Sak' },
  { division: 'Universal', match_code: 'U6', round: 1, winner_pseudo: 'Vertic', loser_pseudo: 'NeroAggelo' }
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
