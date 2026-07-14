/**
 * scrape-scenarios.mjs
 * Genera los JSON de escenarios de batalla desde VS Battle Wiki (Category:Verses)
 *
 * Uso:  node ops/scrape-scenarios.mjs
 * Salida: public/data/scenarios_universal.json
 *         public/data/scenarios_ciudad.json
 *
 * Requiere Node 18+ (fetch nativo)
 */

import { writeFileSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(__dirname, '..', 'public', 'data');

const API = 'https://vsbattles.fandom.com/api.php';
const DELAY_MS = 350; // respeta rate limit de Fandom
const BATCH = 50;     // max IDs por query de pageimages

// ── Clasificación por keywords ──────────────────────────────────────────────
// Universal: escenarios cósmicos, dimensionales, mágicos, épicos
const UNIVERSAL_KEYS = [
  'universe','dimension','cosmos','multiverse','galaxy','nebula','realm',
  'void','space','heaven','hell','afterlife','god','deity','mytholog',
  'magic','dragon','demon','angel','spirit','soul','divine','titan',
  'supernatural','eldritch','astral','primordial','celestial','ancient',
  'legend','myth','immortal','infinite','eternal','alternate','parallel',
  'pocket universe','dark matter','quantum','cosmic','beyond','transcend',
  'fantasy','isekai','dungeon','castle','ruins','temple','shrine','altar',
  'battlefield','arena','colosseum','tournament','war','apocalypse',
];

// Ciudad: escenarios humanos, urbanos, terrenales
const CIUDAD_KEYS = [
  'city','town','school','urban','street','tokyo','new york','paris',
  'london','modern','real world','human','society','police','crime',
  'highschool','high school','college','office','corporation','subway',
  'mall','apartment','neighborhood','village','country','nation','island',
  'japan','america','hospital','laboratory','lab ','military','army',
  'medieval','roman','egypt','ninja','samurai','martial art','delinquent',
  'yakuza','mafia','gangs','underworld','heist','spy','agent','detective',
];

function classifyTier(title, snippet) {
  const text = (title + ' ' + snippet).toLowerCase();
  let uScore = 0;
  let cScore = 0;
  for (const k of UNIVERSAL_KEYS) if (text.includes(k)) uScore++;
  for (const k of CIUDAD_KEYS) if (text.includes(k)) cScore++;
  if (uScore === 0 && cScore === 0) return 'both'; // sin datos claros → ambos
  return uScore >= cScore ? 'universal' : 'ciudad';
}

// ── Helpers de wikitext ─────────────────────────────────────────────────────
function extractDescription(wikitext) {
  if (!wikitext) return '';
  // Busca sección Summary, Background, Overview, Synopsis
  const match = wikitext.match(/==\s*(?:Summary|Background|Overview|Synopsis)\s*==\s*([\s\S]*?)(?:==|$)/i);
  const raw = match ? match[1] : wikitext;
  let txt = raw
    .replace(/\{\{[^{}]*\}\}/g, '')
    .replace(/\[\[(?:[^|\]]*\|)?([^\]]*)\]\]/g, '$1')
    .replace(/'{2,3}/g, '')
    .replace(/<ref[^>]*>[\s\S]*?<\/ref>/gi, '')
    .replace(/<[^>]+>/g, '')
    .replace(/\[https?:[^\]]+\]/g, '')
    .replace(/^[*#:;]+/gm, '')
    .replace(/\n{2,}/g, '\n')
    .trim();
  const lines = txt.split('\n').map(l => l.trim()).filter(l => l.length > 40);
  if (!lines.length) return '';
  const line = lines[0];
  const dot = line.search(/\.\s/);
  return (dot > 20 ? line.slice(0, dot + 1) : line.slice(0, 260)).trim();
}

// ── Fetch con retry ─────────────────────────────────────────────────────────
async function apiFetch(params, attempt = 0) {
  const url = API + '?' + new URLSearchParams({ ...params, format: 'json' });
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': 'BellatorRolBattleScenarioBot/1.0' }
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    if (attempt < 3) {
      await sleep(1000 * (attempt + 1));
      return apiFetch(params, attempt + 1);
    }
    console.error('  ⚠ apiFetch falló:', url, err.message);
    return null;
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Paso 1: colectar todos los IDs de Category:Verses ───────────────────────
async function collectVersePageIds() {
  const ids = [];
  let continueToken = undefined;
  let page = 0;
  console.log('📡 Recolectando IDs de Category:Verses...');
  do {
    page++;
    const params = {
      action: 'query',
      list: 'categorymembers',
      cmtitle: 'Category:Verses',
      cmlimit: '500',
      cmnamespace: '0',
      ...(continueToken ? { cmcontinue: continueToken } : {}),
    };
    const data = await apiFetch(params);
    if (!data?.query?.categorymembers) break;
    const batch = data.query.categorymembers;
    ids.push(...batch.map(m => m.pageid));
    console.log(`  página ${page}: +${batch.length} → total ${ids.length}`);
    continueToken = data.continue?.cmcontinue;
    await sleep(DELAY_MS);
  } while (continueToken);
  console.log(`✅ Total IDs: ${ids.length}`);
  return ids;
}

// ── Paso 2: para cada batch de 50 IDs → thumbnail + wikitext ────────────────
async function fetchBatchData(ids) {
  const idsStr = ids.join('|');
  // Thumbnails
  const imgData = await apiFetch({
    action: 'query',
    pageids: idsStr,
    prop: 'pageimages',
    pithumbsize: '480',
    pilimit: String(ids.length),
  });
  // Wikitext (primer slot, rev actual)
  const wikiData = await apiFetch({
    action: 'query',
    pageids: idsStr,
    prop: 'revisions',
    rvprop: 'content',
  });

  const pages = {};
  // Merge thumbnails
  if (imgData?.query?.pages) {
    for (const [id, pg] of Object.entries(imgData.query.pages)) {
      pages[id] = { ...pages[id], title: pg.title, image: pg.thumbnail?.source || null };
    }
  }
  // Merge wikitext
  if (wikiData?.query?.pages) {
    for (const [id, pg] of Object.entries(wikiData.query.pages)) {
      const wikitext = pg.revisions?.[0]?.['*'] || '';
      pages[id] = { ...pages[id], title: pg.title, wikitext };
    }
  }
  return pages;
}

// ── Paso 3: ensambla escenarios ──────────────────────────────────────────────
function buildScenario(id, title, image, wikitext) {
  const description = extractDescription(wikitext);
  const tier = classifyTier(title, description);
  // Nombre limpio (quita "(Verse)" del final)
  const cleanTitle = title.replace(/\s*\(Verse\)\s*$/i, '').trim();
  return {
    id: Number(id),
    title: cleanTitle,
    source: title,
    image: image || null,
    description: description || `Escenario del universo de ${cleanTitle}.`,
    tier,         // 'universal' | 'ciudad' | 'both'
    tags: [],     // futuro: etiquetas temáticas
  };
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  mkdirSync(OUT_DIR, { recursive: true });

  const allIds = await collectVersePageIds();

  const scenarios = [];
  const totalBatches = Math.ceil(allIds.length / BATCH);

  console.log(`\n🔄 Procesando ${allIds.length} páginas en ${totalBatches} batches de ${BATCH}...`);

  for (let i = 0; i < allIds.length; i += BATCH) {
    const batch = allIds.slice(i, i + BATCH);
    const batchNum = Math.floor(i / BATCH) + 1;
    process.stdout.write(`  batch ${batchNum}/${totalBatches}... `);

    const pages = await fetchBatchData(batch);

    for (const [id, pg] of Object.entries(pages)) {
      if (!pg.title) continue;
      const s = buildScenario(id, pg.title, pg.image, pg.wikitext || '');
      scenarios.push(s);
    }
    console.log(`✓ (total acumulado: ${scenarios.length})`);
    await sleep(DELAY_MS);
  }

  // Separar por tier
  const universal = scenarios.filter(s => s.tier === 'universal' || s.tier === 'both');
  const ciudad    = scenarios.filter(s => s.tier === 'ciudad'    || s.tier === 'both');

  // Shufflea deterministamente por título para variedad
  universal.sort((a, b) => a.title.localeCompare(b.title));
  ciudad.sort((a, b) => a.title.localeCompare(b.title));

  console.log(`\n📊 Resultados:`);
  console.log(`   Universal : ${universal.length} escenarios`);
  console.log(`   Ciudad    : ${ciudad.length} escenarios`);
  console.log(`   Total     : ${scenarios.length} únicos`);

  const uPath = join(OUT_DIR, 'scenarios_universal.json');
  const cPath = join(OUT_DIR, 'scenarios_ciudad.json');

  writeFileSync(uPath, JSON.stringify({ version: 1, generated: new Date().toISOString(), total: universal.length, scenarios: universal }, null, 2));
  writeFileSync(cPath, JSON.stringify({ version: 1, generated: new Date().toISOString(), total: ciudad.length, scenarios: ciudad }, null, 2));

  console.log(`\n✅ Guardado:`);
  console.log(`   ${uPath}`);
  console.log(`   ${cPath}`);
}

main().catch(err => { console.error('❌ Fatal:', err); process.exit(1); });
