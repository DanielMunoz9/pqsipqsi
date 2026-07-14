/**
 * enrich-descriptions.mjs
 * Enriquece los JSON existentes añadiendo las descripciones reales
 * desde la sección "Summary" de cada página de VS Battle Wiki.
 *
 * Uso: node ops/enrich-descriptions.mjs
 */

import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(__dirname, '..', 'public', 'data');
const API = 'https://vsbattles.fandom.com/api.php';
const DELAY_MS = 400;
const BATCH = 20; // wikitext completo es más pesado, batch menor

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function apiFetch(params, attempt = 0) {
  const url = API + '?' + new URLSearchParams({ ...params, format: 'json' });
  try {
    const res = await fetch(url, { headers: { 'User-Agent': 'BellatorRolBattleBot/1.0' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    if (attempt < 3) { await sleep(1000 * (attempt + 1)); return apiFetch(params, attempt + 1); }
    console.error('  ⚠ apiFetch falló:', err.message);
    return null;
  }
}

function extractSummary(wikitext) {
  if (!wikitext) return '';
  // Busca sección Summary o Background
  const match = wikitext.match(/==\s*(?:Summary|Background|Overview|Synopsis)\s*==\s*([\s\S]*?)(?:==|$)/i);
  const raw = match ? match[1] : wikitext;
  // Limpia wikitext
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
  // Primera oración significativa
  const lines = txt.split('\n').map(l => l.trim()).filter(l => l.length > 40);
  if (!lines.length) return '';
  const line = lines[0];
  const dot = line.search(/\.\s/);
  return (dot > 20 ? line.slice(0, dot + 1) : line.slice(0, 260)).trim();
}

async function main() {
  const uPath = join(OUT_DIR, 'scenarios_universal.json');
  const cPath = join(OUT_DIR, 'scenarios_ciudad.json');

  const uData = JSON.parse(readFileSync(uPath, 'utf8'));
  const cData = JSON.parse(readFileSync(cPath, 'utf8'));

  // Merge todos en un mapa por id para enriquecer una sola vez
  const allById = new Map();
  for (const s of uData.scenarios) allById.set(s.id, s);
  for (const s of cData.scenarios) allById.set(s.id, s);

  // Solo los que tienen descripción genérica
  const needsDesc = [...allById.values()].filter(s =>
    !s.description || s.description.startsWith('Escenario del universo')
  );

  console.log(`📝 Enriqueciendo ${needsDesc.length} descripciones de ${allById.size} únicos...`);

  const totalBatches = Math.ceil(needsDesc.length / BATCH);
  let enriched = 0;
  let failed = 0;

  for (let i = 0; i < needsDesc.length; i += BATCH) {
    const batch = needsDesc.slice(i, i + BATCH);
    const batchNum = Math.floor(i / BATCH) + 1;
    const idsStr = batch.map(s => s.id).join('|');

    process.stdout.write(`  batch ${batchNum}/${totalBatches}... `);

    const data = await apiFetch({
      action: 'query',
      pageids: idsStr,
      prop: 'revisions',
      rvprop: 'content',
    });

    if (data?.query?.pages) {
      for (const [id, pg] of Object.entries(data.query.pages)) {
        const wikitext = pg.revisions?.[0]?.['*'] || '';
        const desc = extractSummary(wikitext);
        const numId = Number(id);
        const entry = allById.get(numId);
        if (entry) {
          if (desc) { entry.description = desc; enriched++; }
          else { failed++; }
        }
      }
    }

    console.log(`✓ (enriquecidos: ${enriched}, sin desc: ${failed})`);
    await sleep(DELAY_MS);
  }

  // Re-escribe JSONs con descripciones actualizadas
  // (los objetos en allById son referencias, así que uData/cData ya están actualizados)
  uData.generated = new Date().toISOString();
  cData.generated = new Date().toISOString();

  writeFileSync(uPath, JSON.stringify(uData, null, 2));
  writeFileSync(cPath, JSON.stringify(cData, null, 2));

  console.log(`\n✅ Listo. ${enriched} descripciones añadidas.`);
  console.log(`   ${uPath}`);
  console.log(`   ${cPath}`);
}

main().catch(err => { console.error('❌ Fatal:', err); process.exit(1); });
