const SUPABASE_URL = 'https://sxdckblvilraurcowvbb.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const headers = { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json', 'Prefer': 'return=representation' };

async function go() {
  // 1. Fix upcoming_fights: Prox -> Morwen
  console.log('--- Fixing upcoming_fights ---');
  const r1 = await fetch(`${SUPABASE_URL}/rest/v1/upcoming_fights?player2_pseudo=eq.Prox`, {
    method: 'PATCH', headers,
    body: JSON.stringify({ player2_pseudo: 'Morwen' })
  });
  console.log('upcoming_fights player2 patch:', r1.status);

  const r1b = await fetch(`${SUPABASE_URL}/rest/v1/upcoming_fights?player1_pseudo=eq.Prox`, {
    method: 'PATCH', headers,
    body: JSON.stringify({ player1_pseudo: 'Morwen' })
  });
  console.log('upcoming_fights player1 patch:', r1b.status);

  // 2. Fix bet_fights: Prox -> Morwen
  console.log('--- Fixing bet_fights ---');
  const r2a = await fetch(`${SUPABASE_URL}/rest/v1/bet_fights?fighter_a=eq.Prox`, {
    method: 'PATCH', headers,
    body: JSON.stringify({ fighter_a: 'Morwen' })
  });
  console.log('bet_fights fighter_a patch:', r2a.status);

  const r2b = await fetch(`${SUPABASE_URL}/rest/v1/bet_fights?fighter_b=eq.Prox`, {
    method: 'PATCH', headers,
    body: JSON.stringify({ fighter_b: 'Morwen' })
  });
  console.log('bet_fights fighter_b patch:', r2b.status);

  // Also fix the label if it contains Prox
  const r2c = await fetch(`${SUPABASE_URL}/rest/v1/bet_fights?label=like.*Prox*`, { headers });
  const labelsData = await r2c.json();
  for (const row of labelsData) {
    if (row.label && row.label.includes('Prox')) {
      const newLabel = row.label.replace('Prox', 'Morwen');
      await fetch(`${SUPABASE_URL}/rest/v1/bet_fights?id=eq.${row.id}`, {
        method: 'PATCH', headers,
        body: JSON.stringify({ label: newLabel })
      });
      console.log('Fixed label:', row.label, '->', newLabel);
    }
  }

  // 3. Verify
  console.log('--- Verifying ---');
  const verify1 = await fetch(`${SUPABASE_URL}/rest/v1/upcoming_fights?select=player1_pseudo,player2_pseudo&or=(player1_pseudo.eq.RagnaKurenai,player2_pseudo.eq.RagnaKurenai)`, { headers });
  console.log('RagnaKurenai fight:', await verify1.json());

  const verify2 = await fetch(`${SUPABASE_URL}/rest/v1/bet_fights?select=fighter_a,fighter_b&or=(fighter_a.eq.RagnaKurenai,fighter_b.eq.RagnaKurenai)`, { headers });
  console.log('RagnaKurenai bet_fight:', await verify2.json());
}
go();
