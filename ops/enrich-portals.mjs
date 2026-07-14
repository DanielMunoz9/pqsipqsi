/**
 * enrich-portals.mjs
 * Enriquece los JSON añadiendo un campo `setting` con descripción
 * real del universo y un campo `arena` con una localización concreta
 * para el combate, extraídos de VS Battle Wiki.
 *
 * Uso: node ops/enrich-portals.mjs
 */

import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_DIR   = join(__dirname, '..', 'public', 'data');
const API       = 'https://vsbattles.fandom.com/api.php';
const DELAY_MS  = 450;
const BATCH     = 15; // wikitext completo es pesado
const GENERIC_DESC_RE = /^Escenario del universo/i;
const LOCATION_PHRASE_RE = /\b(?:[A-Z][A-Za-z'’.\-–]+(?:\s+(?:of|the|and|[A-Z][A-Za-z'’.\-–]+)){0,4}\s(?:Island|Islands|Village|City|Town|Kingdom|Realm|World|Court|Academy|Castle|Fortress|Temple|Tower|Forest|Mountain|Valley|Sea|Ocean|Bay|Desert|Jungle|Swamp|Cave|Dungeon|Arena|Palace|Base|Facility|Station|Institute|Laboratory|Country|Domain|Studio|Studios|Borderlands?|Frontier|Badlands|Barrens|Wasteland|Prairie|Plains|Mesa|Canyon|Harbor|Harbour|Port|Factory|Mansion|Manor)|Land\s+Of\s+[A-Z][A-Za-z'’.\-–]+(?:\s+[A-Z][A-Za-z'’.\-–]+){0,2}|[A-Z][A-Za-z'’.\-–]*gakure|The Backrooms|Human Realm|Demon World)\b/gi;
const LOCATION_HINT_RE = /(?:\b(?:Island|Islands|Village|City|Town|Kingdom|Realm|World|Court|Academy|Castle|Fortress|Temple|Tower|Forest|Mountain|Valley|Sea|Ocean|Bay|Desert|Jungle|Swamp|Cave|Dungeon|Arena|Palace|Base|Facility|Station|Institute|Laboratory|Country|Domain|Studio|Studios|Borderlands?|Frontier|Badlands|Barrens|Wasteland|Prairie|Plains|Mesa|Canyon|Harbor|Harbour|Port|Factory|Mansion|Manor)\b|Land\s+Of\s+[A-Z]|gakure\b|The Backrooms\b|Human Realm\b|Demon World\b)/i;
const ARENA_BANNED_RE = /\b(?:summary|story|verse|series|franchise|supporters?|opponents?|neutral|characters?|monsters?|humans?|devices?|groups?|weapons?|notes?|calculations?|gallery|timeline|chapters?|episodes?|novels?|manga|films?|movies?|power|knowledgeable|related|live action|part i|part ii|new era|volume|attack potency|durability|speed|lifting strength|wiki)\b/i;
const ARENA_GENERIC_RE = /^(?:Summary|Story Summary|Series|Characters|Locations?|Setting|Settings|World|Worlds|Geography|Gallery|Notes)$/i;
const ARENA_GENERIC_NAME_RE = /^(?:The|A|An|Real|This|Whole|Strange)\s+(?:World|City|Town|Village|Island|Realm|Kingdom|Court|Domain)$/i;
const SETTING_CUE_RE = /\b(?:set in|set on|set during|takes place|taking place|located in|located on|within|inside|across|through(?:out)?|frontier|borderlands?|desert|wasteland|jungle|forest|mountain|valley|cave|city|village|town|island|studio|studios|academy|laboratory|facility|base|station|fortress|castle|temple|sea|ocean|coast|prairie|plains|mesa|canyon|harbor|harbour|port|american frontier|border region)\b/i;
const SETTING_FOCUS_RE = /\b(?:story\s+focuses|follows|focuses on|centers on|set in|set on|set during|takes place|taking place)\b/i;
const BIBLIOGRAPHIC_RE = /\b(?:written by|illustrated by|published by|premiered|released|serialized|collect(?:ed|ion)|chapters?|volumes?|author|director|producer|developed by|first appeared|television series|manga series|novel by|book,|mobile action rpg|random house|weekly sh\w+n?en jump|shueisha|nintendo|cygames|rko pictures)\b/i;
const GENERIC_IMAGE_RE = /\b(?:logo|cover|book(?:[_ -]?cover)?|title|icon|render|poster|boxart|packshot|emblem|wordmark|banner)\b/i;
const PAGE_FIXES = new Map([
  [2961987, {
    setting: 'The story of the game focuses on Henry, an animator who once worked at Joey Drew Studios. After he is invited back by Joey Drew, he returns to the abandoned workshop, reactivates the Ink Machine and descends through ruined corridors, animation rooms and production floors now overrun by living cartoon horrors.',
    arena: 'Joey Drew Studios',
    image: 'https://static.wikia.nocookie.net/vsbattles/images/5/5e/BendyBendy.png/revision/latest?cb=20260402034309'
  }],
  [5032148, {
    arena: 'United States-Mexico borderlands',
    image: 'https://static.wikia.nocookie.net/vsbattles/images/d/d8/Judge_holden.webp/revision/latest?cb=20230305104011'
  }]
]);

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function apiFetch(params, attempt = 0) {
  const url = API + '?' + new URLSearchParams({ ...params, format: 'json' });
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': 'BellatorRolBattleBot/1.0' },
      signal: AbortSignal.timeout(12000)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    if (attempt < 3) { await sleep(1200 * (attempt + 1)); return apiFetch(params, attempt + 1); }
    console.error('  ⚠ apiFetch falló:', err.message);
    return null;
  }
}

// ── Limpieza de wikitexto ────────────────────────────────────────────
function cleanWiki(raw) {
  return String(raw || '')
    .replace(/<!--([\s\S]*?)-->/g, ' ')                    // comentarios HTML/wiki
    .replace(/\[\[(?:File|Image):[^\]]+\]\]/gi, ' ')    // enlaces de archivo/imagen
    .replace(/\[\[Category:[^\]]+\]\]/gi, ' ')          // categorías wiki
    .replace(/\{\{[^{}]*\}\}/g, '')                          // templates simples
    .replace(/\{\{(?:[^{}]|\{[^{}]*\})*\}\}/g, '')          // templates anidados
    .replace(/\[\[(?:[^|\]]*\|)?([^\]]*)\]\]/g, '$1')       // [[link|texto]] → texto
    .replace(/\[https?:[^\]\s]+(?:\s+([^\]]+))?\]/g, '$1') // [url texto] externo
    .replace(/'{2,3}/g, '')                                  // negrita/itálica wiki
    .replace(/<ref[^>]*>[\s\S]*?<\/ref>/gi, '')             // refs
    .replace(/<ref[^/>]*\/>/gi, '')                           // refs autocerradas
    .replace(/<[^>]+>/g, ' ')                               // otras etiquetas HTML
    .replace(/^(?:Category:[^\n]*)$/gim, ' ')               // líneas sueltas de categorías
    .replace(/^(?:File|Image):[^\n]*$/gim, ' ')              // líneas sueltas de archivos
    .replace(/^\s*[^=\n|]{1,80}=\s*(?:center|thumb|left|right)\|[^\n]*$/gim, ' ')
    .replace(/^\s*(?:center|thumb|left|right)\|[^\n]*$/gim, ' ')
    .replace(/^[*#:;|!]+[ \t]*/gm, '')                      // listas/tablas
    .replace(/\s*\|\s*/g, ' ')
    .replace(/[ \t]{2,}/g, ' ')
    .replace(/\n{2,}/g, '\n')
    .trim();
}

function escapeRegex(text) {
  return String(text || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hasWikiArtifacts(text) {
  return /(?:^|[\s(])(?:File|Image):|(?:^|\s)Category:|\[\[|\{\{|<ref\b|(?:^|\s)(?:thumb|center|left|right)\||^(?:\s*-\s*[^=]{1,80}=){2,}/i.test(text || '');
}

function normalizeSettingText(raw) {
  return cleanWiki(raw)
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
    .join(' ')
    .replace(/\s{2,}/g, ' ')
    .trim();
}

function splitSentences(text) {
  return normalizeSettingText(text)
    .match(/[^.!?]+[.!?]+(?:\s|$)|[^.!?]+$/g)?.map(s => s.trim()).filter(Boolean) || [];
}

function compressSentences(sentences, maxChars = 520, maxSentences = 4) {
  let result = '';
  for (const sentence of sentences) {
    const next = (result + sentence + ' ').trim();
    if (next.length > maxChars || sentence.length < 16) break;
    result = next + ' ';
    if ((result.match(/[.!?]/g) || []).length >= maxSentences) break;
  }
  return result.trim();
}

function pickTerrainSentences(text, maxChars = 520) {
  const sentences = splitSentences(text);
  if (!sentences.length) return '';

  const scored = sentences.map((sentence, index) => {
    let score = 0;
    if (SETTING_CUE_RE.test(sentence)) score += 60;
    if (SETTING_FOCUS_RE.test(sentence)) score += 18;
    if (LOCATION_HINT_RE.test(sentence)) score += 18;
    if (BIBLIOGRAPHIC_RE.test(sentence)) score -= 45;
    return { sentence, index, score };
  });

  const topScore = scored.reduce((best, item) => Math.max(best, item.score), 0);
  const minScore = topScore >= 60 ? topScore - 25 : 1;

  const picked = scored
    .filter(item => item.score >= minScore)
    .sort((a, b) => b.score - a.score || a.index - b.index)
    .slice(0, 4)
    .sort((a, b) => a.index - b.index)
    .map(item => item.sentence);

  if (picked.length) {
    const compressed = compressSentences(picked, maxChars, 3);
    if (compressed.length > 60) return compressed;
  }

  return normalizeSettingText(takeSentences(normalizeSettingText(text), maxChars));
}

function isUsableSetting(text, minLength = 40) {
  return !!text && text.length >= minLength && !hasWikiArtifacts(text);
}

function isRealDescription(text) {
  return !!text && !GENERIC_DESC_RE.test(text);
}

function imageLooksGeneric(text) {
  const normalized = String(text || '')
    .replace(/%20/gi, ' ')
    .replace(/[_-]+/g, ' ')
    .trim();
  return GENERIC_IMAGE_RE.test(normalized);
}

function extractSectionRaw(wikitext, names) {
  for (const name of names) {
    const re = new RegExp(`={2,3}\\s*${name}\\s*={2,3}\\s*([\\s\\S]*?)(?:={2,3}[^=]|$)`, 'i');
    const match = wikitext.match(re);
    if (match) return match[1] || '';
  }
  return '';
}

function sanitizeArenaName(raw) {
  let text = String(raw || '')
    .replace(/[▾]/g, ' ')
    .replace(/^[-*|=:;!\s]+/, '')
    .replace(/[-*|=:;!\s]+$/, ' ');

  text = cleanWiki(text)
    .replace(/\b(?:link=|center|centre|thumb|left|right)\b/gi, ' ')
    .replace(/\((?:Verse|verse|series|franchise)\)/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim();

  if (text.includes(':')) {
    const tail = text.split(':').pop().trim();
    if (LOCATION_HINT_RE.test(tail)) text = tail;
  }

  return text.replace(/\s{2,}/g, ' ').trim();
}

function hasStructuredArenaName(text) {
  const tokens = String(text || '').trim().split(/\s+/).filter(Boolean);
  if (tokens.length === 0 || tokens.length > 5) return false;
  return tokens.every(token => /^(?:of|the|and|from|to|in|on|at|for|de|la|el)$/i.test(token) || /^[A-Z0-9][A-Za-z0-9'’.-]*$/.test(token));
}

function isArenaLikeName(name) {
  const text = sanitizeArenaName(name);
  if (!text || text.length < 3 || text.length > 72) return false;
  if (hasWikiArtifacts(text) || ARENA_GENERIC_RE.test(text) || ARENA_GENERIC_NAME_RE.test(text) || ARENA_BANNED_RE.test(text)) return false;
  if (!hasStructuredArenaName(text)) return false;
  return LOCATION_HINT_RE.test(text);
}

function isUsableArena(text) {
  return isArenaLikeName(text);
}

function extractArenaPhrases(text) {
  const matches = cleanWiki(text).match(LOCATION_PHRASE_RE) || [];
  const unique = new Set();
  for (const match of matches) {
    const name = sanitizeArenaName(match);
    if (isArenaLikeName(name)) unique.add(name);
  }
  return [...unique];
}

function parseSections(wikitext) {
  const headingRe = /^(={2,3})\s*([^=\n]+?)\s*\1\s*$/gm;
  const headings = [];
  let match;

  while ((match = headingRe.exec(wikitext))) {
    headings.push({
      level: match[1].length,
      name: sanitizeArenaName(match[2]),
      start: match.index,
      end: headingRe.lastIndex,
    });
  }

  let currentTop = '';
  return headings.map((entry, index) => {
    if (entry.level === 2) currentTop = entry.name;
    return {
      ...entry,
      topLevel: entry.level === 2 ? entry.name : currentTop,
      sectionText: wikitext.slice(entry.end, index + 1 < headings.length ? headings[index + 1].start : wikitext.length),
    };
  });
}

function arenaScoreBonus(name) {
  if (!name) return 0;
  if (/\b(?:Backrooms|Island|Islands|Forest|Jungle|Village|City|Town|Realm|World|Dimension|Land\s+Of)\b/i.test(name) || /gakure/i.test(name)) return 8;
  if (/\b(?:Castle|Fortress|Temple|Tower|Palace|Institute|Laboratory|Facility|Base|Station|Academy|Court)\b/i.test(name)) return 5;
  return 0;
}

function buildArenaDescription(name, universeTitle) {
  const cleanName = sanitizeArenaName(name);
  const cleanTitle = String(universeTitle || '').replace(/\s*\(Verse\)$/i, '').trim() || 'este universo';
  if (!cleanName) return '';
  if (/backrooms/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, un laberinto liminal de pasillos repetidos, orientación rota y amenazas que castigan cualquier lectura lenta del entorno.`;
  }
  if (/gakure/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, una aldea shinobi fortificada donde los tejados, murallas y accesos estrechos favorecen la movilidad vertical y las emboscadas.`;
  }
  if (/\b(?:Island|Islands)\b/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, una región insular agreste de vegetación densa, desniveles abruptos y cobertura natural impredecible.`;
  }
  if (/\b(?:Forest|Jungle|Swamp|Desert|Mountain|Valley|Cave)\b/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, un entorno natural hostil donde la cobertura, el relieve y la resistencia al terreno pesan tanto como la potencia.`;
  }
  if (/\b(?:City|Town|Court|District|Village)\b/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, un entorno habitado con estructuras, calles y puntos ciegos que premian la lectura táctica del mapa.`;
  }
  if (/\b(?:Realm|World|Domain)\b/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, un dominio de reglas propias donde la adaptación inmediata decide qué combatiente impone el ritmo.`;
  }
  if (/\b(?:Academy|Institute|Laboratory|Facility|Base|Station)\b/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, una instalación cerrada llena de corredores, puntos de estrangulamiento y riesgos estructurales.`;
  }
  if (/\b(?:Studio|Studios|Factory)\b/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, un complejo interior de producción lleno de corredores, salas técnicas y cobertura cerrada.`;
  }
  if (/\b(?:Castle|Fortress|Temple|Tower|Palace)\b/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, una estructura defensiva de pasillos, alturas y zonas de control donde la posición vale tanto como el golpe.`;
  }
  if (/\b(?:Borderlands?|Frontier|Badlands|Barrens|Wasteland|Prairie|Plains|Mesa|Canyon)\b/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, una franja abierta y hostil donde la cobertura es escasa, el relieve manda y cada desplazamiento expone demasiado.`;
  }
  if (/\bLand\s+Of\b/i.test(cleanName)) {
    return `La zona sorteada cae en ${cleanName}, una región extensa y cambiante donde el control del terreno abierto castiga cualquier error de posicionamiento.`;
  }
  return `La zona sorteada cae en ${cleanName}, una localización concreta dentro del universo de ${cleanTitle} donde el entorno puede decidir el ritmo del combate.`;
}

function selectVisualImageCandidates(images) {
  return (images || [])
    .map(img => img?.title || '')
    .filter(title => /^File:/i.test(title))
    .filter(title => !imageLooksGeneric(title))
    .slice(0, 4);
}

function chunkArray(items, size) {
  const chunks = [];
  for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
  return chunks;
}

async function fetchImageInfoMap(fileTitles) {
  const uniqueTitles = [...new Set(fileTitles)].filter(Boolean);
  const result = new Map();

  for (const chunk of chunkArray(uniqueTitles, 15)) {
    const data = await apiFetch({
      action : 'query',
      titles : chunk.join('|'),
      prop   : 'imageinfo',
      iiprop : 'url'
    });

    for (const page of Object.values(data?.query?.pages || {})) {
      const title = page?.title;
      const url = page?.imageinfo?.[0]?.url || '';
      if (title && url) result.set(title, url);
    }
  }

  return result;
}

function extractArena(wikitext, pageTitle) {
  if (!wikitext) return { name: '', description: '' };

  const candidates = new Map();
  let candidateOrder = 0;
  function addCandidate(name, score) {
    const cleanName = sanitizeArenaName(name);
    if (!isArenaLikeName(cleanName)) return;
    const key = cleanName.toLowerCase();
    const nextScore = score + arenaScoreBonus(cleanName);
    const prev = candidates.get(key);
    if (!prev || nextScore > prev.score) {
      candidates.set(key, { name: cleanName, score: nextScore, order: candidateOrder++ });
    }
  }

  const sections = parseSections(wikitext);
  for (const section of sections) {
    if (!section.name) continue;

    if (/^(?:Locations?|Setting|Settings|World|Worlds|Geography)$/i.test(section.name)) {
      extractArenaPhrases(section.sectionText).forEach(name => addCandidate(name, 100));
    }

    if (/^(?:Locations?|Setting|Settings|World|Worlds|Geography|Characters)$/i.test(section.topLevel)) {
      addCandidate(section.name, /^Characters$/i.test(section.topLevel) ? 88 : 95);
    }
  }

  const summaryRaw = extractSectionRaw(wikitext, [
    'Story Summary', 'Summary', 'Synopsis', 'Introduction', 'About', 'Overview', 'Background'
  ]);
  extractArenaPhrases(summaryRaw).forEach(name => addCandidate(name, 80));
  extractArenaPhrases(wikitext.slice(0, 5000)).forEach(name => addCandidate(name, 60));

  const picked = [...candidates.values()].sort((a, b) => b.score - a.score || a.order - b.order)[0];
  if (!picked) return { name: '', description: '' };

  return {
    name: picked.name,
    description: buildArenaDescription(picked.name, pageTitle),
  };
}

// ── Extrae sección por nombre ────────────────────────────────────────
function extractSection(wikitext, names) {
  for (const name of names) {
    // Soporta == Name == y === Name ===
    const re = new RegExp(`={2,3}\\s*${name}\\s*={2,3}\\s*([\\s\\S]*?)(?:={2,3}[^=]|$)`, 'i');
    const m  = wikitext.match(re);
    if (m) {
      const txt = normalizeSettingText(m[1]);
      if (isUsableSetting(txt, 60)) return txt;
    }
  }
  return '';
}

// ── Toma N oraciones de un texto ────────────────────────────────────
function takeSentences(text, maxChars = 520, maxSentences = 5) {
  // Divide en oraciones (punto/excl/interrogación seguido de espacio o fin)
  const parts = text.match(/[^.!?]+[.!?]+(?:\s|$)/g) || [text];
  let result = '';
  for (const s of parts) {
    const candidate = result + s.trim() + ' ';
    if (candidate.length > maxChars || result.split(/[.!?]/).length > maxSentences) break;
    result = candidate;
  }
  return result.trim() || text.slice(0, maxChars).trim();
}

// ── Lógica principal de extracción ──────────────────────────────────
function extractSetting(wikitext, existingDesc) {
  if (!wikitext) return '';

  // 1. Secciones narrativas o de resumen
  const fromNarrative = extractSection(wikitext, [
    'Story Summary', 'Summary', 'Synopsis', 'Introduction',
    'About', 'Overview', 'Background'
  ]);
  if (isUsableSetting(fromNarrative, 80)) {
    const candidate = pickTerrainSentences(fromNarrative, 520);
    if (isUsableSetting(candidate)) return candidate;
  }

  // 2. Secciones específicas de ambientación
  const fromSetting = extractSection(wikitext, [
    'Setting', 'Settings', 'Environments', 'Environment',
    'World', 'Worlds', 'Geography', 'Universe'
  ]);
  if (isUsableSetting(fromSetting, 80)) {
    const candidate = pickTerrainSentences(fromSetting, 520);
    if (isUsableSetting(candidate)) return candidate;
  }

  // 3. Ubicaciones, solo como último recurso porque suelen ser galerías
  const fromLocation = extractSection(wikitext, ['Locations', 'Location']);
  if (isUsableSetting(fromLocation, 80)) {
    const candidate = pickTerrainSentences(fromLocation, 520);
    if (isUsableSetting(candidate)) return candidate;
  }

  // 4. Regex de secciones-resumen como fallback extra
  const sumMatch = wikitext.match(
    /={2,3}\s*(?:Story Summary|Summary|Synopsis|Introduction|About|Overview|Background)\s*={2,3}\s*([\s\S]*?)(?:={2,3}[^=]|$)/i
  );
  if (sumMatch) {
    const txt = normalizeSettingText(sumMatch[1]);
    if (isUsableSetting(txt, 80)) {
      const candidate = pickTerrainSentences(txt, 520);
      if (isUsableSetting(candidate)) return candidate;
    }
  }

  // 5. Primeras líneas del artículo (antes de la primera sección)
  const beforeSections = wikitext.split(/={2,3}/)[0];
  const intro = normalizeSettingText(beforeSections);
  if (isUsableSetting(intro, 80)) {
    const candidate = pickTerrainSentences(intro, 520);
    if (isUsableSetting(candidate)) return candidate;
  }

  // 6. Fallback: descripción existente (si es real)
  if (isRealDescription(existingDesc)) {
    return existingDesc.slice(0, 520);
  }

  return '';
}

// ── Main ─────────────────────────────────────────────────────────────
async function main() {
  const uPath = join(OUT_DIR, 'scenarios_universal.json');
  const cPath = join(OUT_DIR, 'scenarios_ciudad.json');

  const uData = JSON.parse(readFileSync(uPath, 'utf8'));
  const cData = JSON.parse(readFileSync(cPath, 'utf8'));

  // Mapa id → escenarios (universal y ciudad pueden compartir id)
  const allById = new Map();
  function addScenarioRef(s) {
    const refs = allById.get(s.id) || [];
    refs.push(s);
    allById.set(s.id, refs);
  }
  for (const s of uData.scenarios) addScenarioRef(s);
  for (const s of cData.scenarios) addScenarioRef(s);

  // Procesar todos los que no tengan `setting`, no tengan `arena`
  // o conserven texto claramente inválido.
  const needs = [...allById.entries()]
    .filter(([, refs]) => refs.some(s => !isUsableSetting(s.setting) || !isUsableArena(s.arena) || !s.image || imageLooksGeneric(s.image)))
    .map(([id, refs]) => ({
      id,
      refs,
      description: refs.find(s => isRealDescription(s.description))?.description || ''
    }));

  console.log(`🌍 Enriqueciendo setting de ${needs.length} escenarios...`);

  const totalBatches = Math.ceil(needs.length / BATCH);
  let enriched = 0;
  let failed   = 0;

  for (let i = 0; i < needs.length; i += BATCH) {
    const batch    = needs.slice(i, i + BATCH);
    const batchNum = Math.floor(i / BATCH) + 1;
    const idsStr   = batch.map(s => s.id).join('|');
    const batchById = new Map(batch.map(item => [item.id, item]));

    process.stdout.write(`  batch ${batchNum}/${totalBatches}... `);

    const data = await apiFetch({
      action  : 'query',
      pageids : idsStr,
      prop    : 'revisions|images',
      rvprop  : 'content',
      rvslots : 'main',
      imlimit : '10'
    });

    if (data?.query?.pages) {
      const pages = Object.entries(data.query.pages);
      const imageCandidatesById = new Map();
      const imageTitles = [];

      for (const [id, pg] of pages) {
        const numId = Number(id);
        const entrySet = batchById.get(numId);
        if (!entrySet) continue;
        if (entrySet.refs.some(entry => !entry.image || imageLooksGeneric(entry.image))) {
          const candidates = selectVisualImageCandidates(pg.images);
          if (candidates.length) {
            imageCandidatesById.set(numId, candidates);
            candidates.forEach(title => imageTitles.push(title));
          }
        }
      }

      const imageInfoMap = imageTitles.length ? await fetchImageInfoMap(imageTitles) : new Map();

      for (const [id, pg] of pages) {
        const wikitext = pg.revisions?.[0]?.slots?.main?.['*']
                      || pg.revisions?.[0]?.['*']
                      || '';
        const numId  = Number(id);
        const entrySet = batchById.get(numId);
        if (!entrySet) continue;

        const pageFix = PAGE_FIXES.get(numId) || null;
        const setting = extractSetting(wikitext, entrySet.description || '');
        const arena = extractArena(wikitext, pg.title || entrySet.refs[0]?.title || '');
        const betterImage = (imageCandidatesById.get(numId) || []).map(title => imageInfoMap.get(title)).find(Boolean) || '';
        const finalSetting = pageFix?.setting || setting;
        const finalArena = pageFix?.arena || arena.name;
        const finalImage = pageFix?.image || betterImage;
        const updated = !!finalSetting || !!finalArena || !!finalImage;

        entrySet.refs.forEach(entry => {
          entry.setting = finalSetting || (isUsableSetting(entry.setting) ? entry.setting : '');
          entry.arena = finalArena || (isUsableArena(entry.arena) ? entry.arena : '');
          if (finalImage && (!entry.image || imageLooksGeneric(entry.image) || pageFix?.image)) entry.image = finalImage;
        });

        if (updated) {
          enriched++;
        } else {
          failed++;
        }
      }
    }

    console.log(`✓ (con setting: ${enriched}, sin dato: ${failed})`);

    // Guardar progreso cada 10 batches por si se interrumpe
    if (batchNum % 10 === 0) {
      uData.generated = new Date().toISOString();
      cData.generated = new Date().toISOString();
      writeFileSync(uPath, JSON.stringify(uData, null, 2));
      writeFileSync(cPath, JSON.stringify(cData, null, 2));
      process.stdout.write('  💾 progreso guardado\n');
    }

    await sleep(DELAY_MS);
  }

  // Guardar final
  uData.generated = new Date().toISOString();
  cData.generated = new Date().toISOString();
  writeFileSync(uPath, JSON.stringify(uData, null, 2));
  writeFileSync(cPath, JSON.stringify(cData, null, 2));

  console.log(`\n✅ Listo. ${enriched} settings añadidos, ${failed} sin dato.`);
}

main().catch(err => { console.error('❌ Fatal:', err); process.exit(1); });
