// check-rev-format.mjs - v2
const API = 'https://vsbattles.fandom.com/api.php';
const params = new URLSearchParams({
  action: 'query',
  pageids: '311995|14088',
  prop: 'revisions',
  rvprop: 'content',
  format: 'json',
});
const r = await fetch(API + '?' + params, { headers: { 'User-Agent': 'Test/1.0' } });
const raw = await r.json();
if (raw.error) { console.log('Error:', raw.error); process.exit(1); }
for (const [id, pg] of Object.entries(raw.query.pages)) {
  const rev = pg.revisions?.[0];
  console.log('--- Title:', pg.title);
  console.log('Rev keys:', JSON.stringify(Object.keys(rev || {})));
  const content = rev?.['*'] || rev?.slots?.main?.['*'] || '';
  console.log('Content len:', content.length);
  const sumMatch = content.match(/==\s*Summary\s*==\s*([\s\S]*?)(?:==|$)/i);
  if (sumMatch) {
    const txt = sumMatch[1].replace(/\[\[(?:[^|\]]*\|)?([^\]]*)\]\]/g, '$1').replace(/\{\{[^{}]*\}\}/g, '').trim();
    console.log('Summary:', txt.slice(0, 150));
  } else {
    const secs = [...content.matchAll(/^==([^=]+)==/gm)].map(m => m[1].trim());
    console.log('Sections:', secs.join(' | '));
    console.log('First 200:', content.slice(0, 200));
  }
}
