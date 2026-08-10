const S='https://sxdckblvilraurcowvbb.supabase.co';
const K='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN4ZGNrYmx2aWxyYXVyY293dmJiIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3NDg4MjIzOSwiZXhwIjoyMDkwNDU4MjM5fQ.gXb0qwNuBixQh33DOH20AMSjaQmUP1cP02_Hj69NHwA';
const h = {apikey:K, Authorization:'Bearer '+K, 'Accept-Profile':'album'};

async function go(){
  // Try app_config keys (paginated)
  const r = await fetch(S+'/rest/v1/app_config?select=key&limit=200', {headers: {...h, 'Range': '0-199'}});
  console.log('app_config status:', r.status);
  const txt = await r.text();
  try {
    const d = JSON.parse(txt);
    if (Array.isArray(d)) {
      console.log('app_config keys (' + d.length + '):');
      d.forEach(x => console.log(' ', x.key));
    } else {
      console.log('Response:', txt.substring(0, 500));
    }
  } catch(e) {
    console.log('Raw:', txt.substring(0, 500));
  }

  // Check for v_current_roster (all registered players)
  const r2 = await fetch(S+'/rest/v1/v_current_roster?select=pseudonimo&limit=200', {headers: {apikey:K, Authorization:'Bearer '+K}});
  const roster = await r2.json();
  console.log('\nv_current_roster total:', Array.isArray(roster) ? roster.length : 'not array');

  // Check aspirantes
  const r3 = await fetch(S+'/rest/v1/aspirantes?select=pseudonimo&limit=200', {headers: {apikey:K, Authorization:'Bearer '+K}});
  const asp = await r3.json();
  console.log('aspirantes total:', Array.isArray(asp) ? asp.length : 'not array');
}
go();
