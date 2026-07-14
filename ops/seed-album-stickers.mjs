/**
 * MÓDULO 2 — Seed: Album Stickers
 * Genera los cromos del álbum Bellator RolBattle a partir de los jugadores activos.
 *
 * Cada jugador produce 8 filas en album.stickers:
 *   - player  normal
 *   - char_1  normal
 *   - char_2  normal
 *   - char_3  normal
 *   - player  dorado
 *   - char_1  dorado
 *   - char_2  dorado
 *   - char_3  dorado
 *
 * Uso:
 *   node ops/seed-album-stickers.mjs
 *
 * Variables de entorno necesarias (mismo .env que el proyecto):
 *   SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE_KEY
 *   API_BASE_URL   (ej: https://bellatorrpg.online  o  http://localhost:8080)
 */

import { createClient } from '@supabase/supabase-js';

// ─── CONFIG ──────────────────────────────────────────────────────────
const SUPABASE_URL             = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const API_BASE_URL             = process.env.API_BASE_URL || 'http://localhost:8080';
const SERIES                   = '2026';

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('❌  Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

const ALBUM_EXCLUDED_PLAYERS = new Set([
  'bandet997883',
  'demon usser',
  'eisengaard',
  'jhon ridley',
  'metasploit',
  'morwen',
  'nilu',
  'primrose',
  'ryu',
  'shin kazami',
  'sekiro',
  'xiao',
  '𝖂indham'.toLowerCase(),
  'windham',
]);

const DIVISION_ORDER = { universal: 0, ciudad: 1 };

function normalizePseudoKey(value = '') {
  return String(value || '').trim().toLowerCase();
}

function shouldIncludeAlbumPlayer(player) {
  const pseudoKey = normalizePseudoKey(player && player.pseudonimo);
  if (!pseudoKey || ALBUM_EXCLUDED_PLAYERS.has(pseudoKey)) {
    return false;
  }
  return [1, 2, 3].some((index) => String(player?.[`top_char_${index}`] || '').trim() !== '');
}

function compareAlbumPlayers(left, right) {
  const leftDivision = DIVISION_ORDER[normalizeDivision(left?.division)] ?? 99;
  const rightDivision = DIVISION_ORDER[normalizeDivision(right?.division)] ?? 99;
  if (leftDivision !== rightDivision) return leftDivision - rightDivision;

  const leftPoints = Number(left?.ranking_points || 0);
  const rightPoints = Number(right?.ranking_points || 0);
  if (leftPoints !== rightPoints) return rightPoints - leftPoints;

  const leftWins = Number(left?.wins || 0);
  const rightWins = Number(right?.wins || 0);
  if (leftWins !== rightWins) return rightWins - leftWins;

  return String(left?.pseudonimo || '').localeCompare(String(right?.pseudonimo || ''), 'es', { sensitivity: 'base' });
}

// ─── RAREZA basada en stats del jugador ──────────────────────────────
/**
 * Reglas:
 *   legendario → wins >= 10  OR  ranking_points >= 100
 *   epico      → wins >= 5   OR  current_streak >= 3
 *   raro       → wins >= 2
 *   comun      → resto
 *
 * Los cromos de personaje heredan la rareza del jugador.
 * Si el personaje tiene imagen propia, sube 1 nivel (max legendario).
 */
function calcRarity(player) {
  const { wins = 0, ranking_points = 0, current_streak = 0 } = player;
  if (wins >= 10 || ranking_points >= 100) return 'legendario';
  if (wins >= 5  || current_streak >= 3)   return 'epico';
  if (wins >= 2)                            return 'raro';
  return 'comun';
}

const RARITY_RANK = { comun: 0, raro: 1, epico: 2, legendario: 3 };
const RARITY_UP   = ['comun', 'raro', 'epico', 'legendario'];

function upgradeRarity(base) {
  const idx = RARITY_RANK[base] ?? 0;
  return RARITY_UP[Math.min(idx + 1, 3)];
}

// ─── CONSTRUIR FILAS para un jugador ─────────────────────────────────
function buildStickersForPlayer(player, slotBase) {
  const baseRarity = calcRarity(player);

  // Los 4 tipos de cromo
  const types = [
    {
      type:        'player',
      displayName: player.pseudonimo,
      imageUrl:    player.avatar_url || null,
      rarity:      baseRarity,
    },
    {
      type:        'char_1',
      displayName: player.top_char_1 || '???',
      imageUrl:    player.top_char_1_image || null,
      rarity:      player.top_char_1 ? upgradeRarity(baseRarity) : 'comun',
    },
    {
      type:        'char_2',
      displayName: player.top_char_2 || '???',
      imageUrl:    player.top_char_2_image || null,
      rarity:      player.top_char_2 ? upgradeRarity(baseRarity) : 'comun',
    },
    {
      type:        'char_3',
      displayName: player.top_char_3 || '???',
      imageUrl:    player.top_char_3_image || null,
      rarity:      player.top_char_3 ? upgradeRarity(baseRarity) : 'comun',
    },
  ];

  const rows = [];
  
  // Versión Épica garantizada (una por jugador, en slot separado)
  rows.push({
    series:       SERIES,
    player_pseudo: player.pseudonimo,
    division:     normalizeDivision(player.division),
    sticker_type: 'player',
    variant:      'epico',
    special_type: 'normal',
    display_name: player.pseudonimo,
    image_url:    player.avatar_url || null,
    rarity:       'epico',
    slot_number:  slotBase + 500,
    max_copies:   null,
  });

  types.forEach((t, i) => {
    // Versión normal
    rows.push({
      series:       SERIES,
      player_pseudo: player.pseudonimo,
      division:     normalizeDivision(player.division),
      sticker_type: t.type,
      variant:      'normal',
      display_name: t.displayName,
      image_url:    t.imageUrl,
      rarity:       t.rarity,
      slot_number:  slotBase + i,
      max_copies:   null,   // ilimitado
    });

    // Versión dorada (ultra-rara, 1 copia por jugador en todo el juego)
    rows.push({
      series:       SERIES,
      player_pseudo: player.pseudonimo,
      division:     normalizeDivision(player.division),
      sticker_type: t.type,
      variant:      'dorado',
      display_name: t.displayName,
      image_url:    t.imageUrl,
      rarity:       'legendario',  // las doradas siempre son legendarias
      slot_number:  slotBase + i + 1000, // espacio separado para doradas
      max_copies:   1,              // solo 1 existe en todo el juego
    });
  });

  return rows;
}

function normalizeDivision(raw = '') {
  const v = raw.toLowerCase();
  if (v.includes('ciudad')) return 'ciudad';
  return 'universal';
}

// ─── MAIN ─────────────────────────────────────────────────────────────
async function main() {
  console.log('🔍  Obteniendo jugadores desde', API_BASE_URL + '/api/competidores');

  let players;
  try {
    const res = await fetch(API_BASE_URL + '/api/competidores');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    players = await res.json();
  } catch (err) {
    console.error('❌  Error al obtener jugadores:', err.message);
    process.exit(1);
  }

  if (!Array.isArray(players) || players.length === 0) {
    console.error('❌  No se recibieron jugadores (array vacío)');
    process.exit(1);
  }

  console.log(`✅  ${players.length} jugadores encontrados`);

  const filteredPlayers = players
    .filter((player) => shouldIncludeAlbumPlayer(player))
    .sort(compareAlbumPlayers);

  const excludedCount = players.length - filteredPlayers.length;
  if (!filteredPlayers.length) {
    console.error('❌  No quedaron jugadores válidos para el álbum después del filtro exclusivo');
    process.exit(1);
  }

  console.log(`🧹  ${excludedCount} jugadores excluidos del álbum; ${filteredPlayers.length} quedan en el roster exclusivo`);

  const excludedPseudos = filteredPlayers.map((player) => normalizePseudoKey(player.pseudonimo));
  const { error: deleteError } = await supabase
    .schema('album')
    .from('stickers')
    .delete()
    .eq('series', SERIES)
    .eq('special_type', 'normal')
    .not('player_pseudo', 'in', `(${filteredPlayers.map((player) => JSON.stringify(String(player.pseudonimo))).join(',')})`);

  if (deleteError) {
    console.error('❌  Error limpiando jugadores colados del catálogo:', deleteError.message);
    process.exit(1);
  }

  // ── Generar todas las filas ────────────────────────────────────────
  const allRows = [];
  filteredPlayers.forEach((player, idx) => {
    if (!player.pseudonimo) return;
    const slotBase = (idx + 1) * 10;  // BEL-010, BEL-020, etc.
    const rows = buildStickersForPlayer(player, slotBase);
    allRows.push(...rows);
  });

  console.log(`📦  ${allRows.length} cromos a insertar (${filteredPlayers.length} jugadores × 8)`);

  // ── Upsert en Supabase ─────────────────────────────────────────────
  // onConflict: si ya existe el cromo (mismo jugador+tipo+variante+serie) actualiza
  const BATCH = 50;
  let inserted = 0;
  let errors   = 0;

  for (let i = 0; i < allRows.length; i += BATCH) {
    const batch = allRows.slice(i, i + BATCH);
    const { error } = await supabase
      .schema('album')
      .from('stickers')
      .upsert(batch, {
        onConflict: 'player_pseudo,sticker_type,variant,series',
        ignoreDuplicates: false,
      });

    if (error) {
      console.error(`❌  Error en batch ${i}-${i + BATCH}:`, error.message);
      errors += batch.length;
    } else {
      inserted += batch.length;
      process.stdout.write(`   Insertados: ${inserted}/${allRows.length}\r`);
    }
  }

  console.log('\n');
  if (errors > 0) {
    console.warn(`⚠️   ${errors} cromos fallaron`);
  }
  console.log(`✅  Seed completado — ${inserted} cromos en album.stickers`);

  // ── Resumen por rareza ─────────────────────────────────────────────
  const summary = allRows.reduce((acc, r) => {
    const key = `${r.variant}-${r.rarity}`;
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});

  console.log('\n📊  Distribución:');
  Object.entries(summary)
    .sort(([a], [b]) => a.localeCompare(b))
    .forEach(([k, v]) => console.log(`   ${k.padEnd(25)} ${v}`));
}

main();
