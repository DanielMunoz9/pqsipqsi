import fs from 'fs';
const SUPABASE_URL = 'https://sxdckblvilraurcowvbb.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const headers = { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` };

async function go() {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/v_current_roster?limit=1000`, { headers });
  const data = await res.json();
  const names = Array.from(new Set(data.map(d => d.pseudonimo).filter(Boolean)));
  fs.writeFileSync('c:/Users/Daniel/Desktop/valhala/players.json', JSON.stringify(names, null, 2));
  console.log('Got ' + names.length + ' pseudos from v_current_roster.');
}
go();
