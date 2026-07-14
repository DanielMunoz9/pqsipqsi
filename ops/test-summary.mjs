// test-summary.mjs
const API = 'https://vsbattles.fandom.com/api.php';
const r = await fetch(API + '?action=query&pageids=311995&prop=revisions&rvprop=content&rvslots=main&rvlimit=1&format=json', { headers: {'User-Agent':'Test/1.0'} });
const d = await r.json();
const wiki = d.query.pages['311995']?.revisions?.[0]?.slots?.main?.['*'] || '';

const sumMatch = wiki.match(/==\s*Summary\s*==\s*([\s\S]*?)(?:==|$)/i);
if (sumMatch) {
  let txt = sumMatch[1]
    .replace(/\[\[(?:[^|\]]*\|)?([^\]]*)\]\]/g, '$1')
    .replace(/\{\{[^{}]*\}\}/g, '')
    .replace(/'{2,3}/g, '')
    .replace(/<[^>]+>/g, '')
    .trim();
  console.log('Summary (Akira):', txt.slice(0, 300));
} else {
  console.log('No Summary. Secciones:', [...wiki.matchAll(/^==([^=]+)==/gm)].map(m => m[1].trim()).join(' | '));
}
