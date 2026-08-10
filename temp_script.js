
const LEGACY_PLAYER_KEY_STORAGE_KEY = 'valhala_album_player_key';
const PSEUDONIMO_STORAGE_KEY = 'valhala_album_player_pseudonimo';
const LOCAL_SESSION_STORAGE_KEY = 'valhala_album_local_session_v1';
const ALBUM_SESSION_TOKEN_STORAGE_KEY = 'valhala_album_session_token_v1';
const TRADE_REQUESTS_STORAGE_KEY = 'valhala_album_trade_requests_v1';
const PREVIEW_COLLECTION_KEY = 'valhala_album_preview_collection_v1';
const DAILY_PACK_STORAGE_KEY = 'valhala_album_daily_free_packs_v1';
const DAILY_ACTIVITY_STORAGE_KEY = 'valhala_album_daily_activity_v1';
const PENDING_STICKERS_KEY = 'valhala_album_pending_stickers_v1';
const MISSION_CONFIG_STORAGE_KEY = 'valhala_album_mission_config_v1';
const SOUNDTRACK_STORAGE_KEY = 'valhala_album_soundtrack_v1';
function previewCollectionStorageKey() {
  return `${PREVIEW_COLLECTION_KEY}:${albumIdentityStorageKey()}`;
}

function pendingStickerStorageKey() {
  return `${PENDING_STICKERS_KEY}:${albumIdentityStorageKey()}`;
}
const PREVIEW_PACK_SIZE = 3;
const DAILY_FREE_PACK_LIMIT = 2;
const DIVISION_ORDER = { universal: 0, ciudad: 1 };
const ALBUM_EXCLUDED = new Set(['BANDET997883', 'Demon Usser', 'Eisengaard', 'Jhon Ridley', 'Metasploit', 'Morwen', 'nilu', 'primrose', 'ryu', 'Shin Kazami', 'Sekiro', 'xiao', '𝖂indham', 'Windham'].map((value) => value.toLowerCase()));
const ROSTER_RARITY_ORDER = { comun: 0, raro: 1, epico: 2, legendario: 3, iconico: 4 };
const ROSTER_RARITY_UP = ['comun', 'raro', 'epico', 'legendario'];
const ICONIC_DROP_PERCENT = 3; // 3% por sobre
// Override de avatares locales por pseudónimo (case-insensitive)
const AVATAR_OVERRIDES = {
  'khamzat': 'STICKERS/00c51ca3fc2408a1795e91ad23c5dc35.webp',
};

// ✦ ICONOS DE LEYENDA — cromos ultra raros (≈3% por sobre). Cada uno es su propia página.
const ICONIC_LEGACIES = {
  orochi: {
    label: 'Orochi Legacy',
    tag: 'LEGENDARY CLAN',
    order: -200,
    accent: '#f0b429',
    accent2: '#3a1c05',
    story: 'The Orochi Legacy is the most decorated clan in the Battly — a dynasty that imposed its law across an entire era. Collecting its icons is not just holding history: it grants real advantages in Bellator through their extreme rarity. Every Orochi in your album is a throne earned.',
  },
  iconos: {
    label: 'Bellator Icons',
    tag: 'ETERNAL FIGURES',
    order: -100,
    accent: '#e30613',
    accent2: '#33060a',
    story: 'Figures who transcended the Battle and became living legend. Ultra-rare pulls (~3% per pack): to own them is pure history and status inside Bellator.',
  },
};

const ICONIC_LEGENDS = [
  {
    id: 'iconic-bandet', name: 'BANDET', legacy: 'orochi',
    image: 'STICKERS/images (2).jpg',
    position: 'PRIME', rating: 109, country: '',
    tagline: 'Pure talent, always the best',
    lore: 'In raw talent, Bandet always stood a step above everyone. He never chased greatness — greatness followed him into every arena of the Battle. When the pressure was highest, his gift was purest.',
    powers: ['+15% de energía', '-15% de energía rival', '1 hax prohibido desbloqueado'],
    accent: '#c8102e', accent2: '#3a0a12',
  },
  {
    id: 'iconic-ember', name: 'EMBER', legacy: 'orochi',
    image: 'STICKERS/c2f6893d011ee2e7fd339ca50300a964.jpg',
    position: 'MIND', rating: 108, country: '',
    tagline: 'The one who knew the most',
    lore: 'The mind of the Orochi Legacy. Ember read every fight before it happened: the one who knew the most, the one who never improvised. Where others saw chaos, he saw the whole script.',
    powers: ['+10 de vida', '+1 ataque limit tier en el mismo turno', '2 turnos límite seguidos sin gastar la energía de 1'],
    accent: '#ff7a1a', accent2: '#3a1c05',
  },
  {
    id: 'iconic-merus', name: 'MERUS', legacy: 'orochi',
    image: 'STICKERS/979643e71d81be19038c415e8ad98bd2.jpg',
    position: 'BRAVE', rating: 108, country: '',
    tagline: 'The bravest of them all',
    lore: 'Where others hesitated, Merus advanced. The bravest of the Orochi Legacy: first on every line and last to surrender. His courage set the tempo for the entire clan.',
    powers: ['Ruptura de defensa total', '-20 de HP al rival', 'Aturdimiento: -25% de velocidad de reacción enemiga'],
    accent: '#2f6bff', accent2: '#0a1533',
  },
  {
    id: 'iconic-akira', name: 'AKIRA', legacy: 'orochi',
    image: 'STICKERS/29773f4d994905a1785a3ee990d181c8.jpg',
    position: 'JEWEL', rating: 109, country: '',
    tagline: 'Forever the jewel',
    lore: 'The eternal jewel of the Orochi Legacy. Talent and shine that time cannot fade: Akira always was, and always will be, the jewel of the clan. Pure elegance turned into legend.',
    powers: ['+20 de energía', 'Mano blanca absoluta', '+Null Power: bloqueo absoluto de un poder'],
    accent: '#25d0c0', accent2: '#04302c',
  },
  {
    id: 'iconic-ego', name: 'EGO', legacy: 'iconos',
    image: 'STICKERS/648182651_122223086078282233_1385444020102020884_n.jpg',
    position: 'MASTER', rating: 110, country: '',
    tagline: 'The most respected master',
    lore: 'A master whose name commands silence. Ego earned respect not through force but through mastery — every technique refined, every lesson eternal. To face her was to learn; to earn her nod was legend itself.',
    powers: ['+1 hax prohibido', '+12 horas de respuesta'],
    accent: '#a855f7', accent2: '#1f0a33',
  },
  {
    id: 'iconic-inverse', name: 'INVERSE BERKANSTEL', legacy: 'iconos',
    image: 'STICKERS/l4xiji7ms0991.png',
    position: 'ELITE', rating: 110, country: '',
    tagline: 'A level apart',
    lore: 'Inverse Berkanstel played in a different dimension. His level was never compared: it was admired. Every appearance redefined the ceiling of the Battle and made clear exactly where the summit stood.',
    powers: ['+20 de vida', '+15 de energía', '+15 de resistencia'],
    accent: '#7a2bff', accent2: '#1a0733',
  },
  {
    id: 'iconic-reddraig', name: 'RED DRAIG CRIMSON', legacy: 'iconos',
    image: 'STICKERS/HD-wallpaper-god-of-high-school-jin-jin-mori.jpg',
    position: 'BOSS', rating: 110, country: '',
    tagline: 'Top of the hierarchy',
    lore: 'At the peak of his clan hierarchy, Red Draig Crimson dictated the law of the Crimson. His word was rank and his presence was order: the absolute apex of his lineage.',
    powers: ['+25% de potencia de ataque', '+15% de velocidad', 'El bonus escala según el tier'],
    accent: '#e30613', accent2: '#33060a',
  },
];

function buildIconicStickers() {
  return ICONIC_LEGENDS.map((legend, index) => {
    const legacy = ICONIC_LEGACIES[legend.legacy] || ICONIC_LEGACIES.iconos;
    return {
      id: legend.id,
      series: '2026',
      groupKey: `iconic-${legend.legacy}`,
      groupLabel: legacy.label,
      groupOrder: (legacy.order || -100) + index,
      playerPseudo: legend.name,
      division: legacy.label,
      stickerType: 'player',
      variant: 'iconico',
      displayName: legend.name,
      imageUrl: legend.image,
      rarity: 'iconico',
      slotNumber: 900 + index,
      quantity: 0,
      collected: false,
      isNew: false,
      primaryColor: legend.accent,
      wins: 0, losses: 0, draws: 0, currentStreak: 0, rankingPoints: 0,
      clanName: legacy.label,
      countryCode: legend.country || '',
      // Campos de leyenda
      isIconic: true,
      legacyKey: legend.legacy,
      legacyLabel: legacy.label,
      legacyTag: legacy.tag,
      legacyStory: legacy.story,
      legendTagline: legend.tagline,
      legendLore: legend.lore,
      legendPowers: Array.isArray(legend.powers) ? legend.powers.slice() : [],
      legendRating: legend.rating,
      legendPosition: legend.position,
      legendAccent: legend.accent,
      legendAccent2: legend.accent2,
    };
  });
}

function cleanUnicodeStyles(str) {
  if (!str) return '';
  let out = '';
  for (let i = 0; i < str.length; i++) {
    const cp = str.codePointAt(i);
    if (cp > 0xffff) i++;
    
    if (cp >= 0x1d400 && cp <= 0x1d419) {
      out += String.fromCharCode(65 + (cp - 0x1d400));
    } else if (cp >= 0x1d41a && cp <= 0x1d433) {
      out += String.fromCharCode(97 + (cp - 0x1d41a));
    } else if (cp >= 0x1d586 && cp <= 0x1d59f) {
      out += String.fromCharCode(65 + (cp - 0x1d586));
    } else if (cp >= 0x1d5a0 && cp <= 0x1d5b9) {
      out += String.fromCharCode(97 + (cp - 0x1d5a0));
    } else if (cp >= 0x1d63c && cp <= 0x1d655) {
      out += String.fromCharCode(65 + (cp - 0x1d63c));
    } else if (cp >= 0x1d656 && cp <= 0x1d66f) {
      out += String.fromCharCode(97 + (cp - 0x1d656));
    } else if (cp >= 0x1d5d4 && cp <= 0x1d5ed) {
      out += String.fromCharCode(65 + (cp - 0x1d5d4));
    } else if (cp >= 0x1d5ee && cp <= 0x1d607) {
      out += String.fromCharCode(97 + (cp - 0x1d5ee));
    } else {
      if (cp === 120199) { out += 'B'; continue; }
      if (cp === 120456) { out += 'M'; continue; }
      if (cp === 120072) { out += 'E'; continue; }
      if (cp === 120085) { out += 'R'; continue; }
      if (cp === 120088) { out += 'U'; continue; }
      if (cp === 0x1d598) { out += 'm'; continue; }
      if (cp === 120086) { out += 'S'; continue; }
      out += String.fromCodePoint(cp);
    }
  }
  return out;
}

function normalizeString(str) {
  if (!str) return '';
  return cleanUnicodeStyles(str).toLowerCase().replace(/[^a-z0-9]/g, '').trim();
}

function iconicStickersWithCollection(serverStickers) {
  const coll = state.catalogMode === 'server' ? null : loadPreviewCollection();
  return buildIconicStickers().map((sticker) => {
    let quantity = 0;
    if (state.catalogMode === 'server' && Array.isArray(serverStickers)) {
      const cleanStatic = normalizeString(sticker.playerPseudo);
      const matched = serverStickers.find(s => 
        safeText(s.specialType, '').toLowerCase() === 'iconico' && 
        normalizeString(s.playerPseudo).replace(/_?icon$/, '') === cleanStatic
      );
      if (matched) {
        quantity = Number(matched.quantity || 0);
        sticker.id = matched.id; // UPDATE TO SERVER ID
        if (matched.imageUrl) sticker.imageUrl = matched.imageUrl;
      }
    } else if (coll) {
      quantity = Number(coll[sticker.id] || 0);
    }
    return { ...sticker, quantity, collected: quantity > 0, isNew: false };
  });
}

function pickIconicDrop() {
  const coll = loadPreviewCollection();
  const all = buildIconicStickers();
  const unowned = all.filter((legend) => !(Number(coll[legend.id] || 0) > 0));
  const pool = unowned.length ? unowned : all;
  const picked = pool[randomIndex(pool.length)] || null;
  if (picked && Array.isArray(state.stickers)) {
    const srv = state.stickers.find(s => s.specialType === 'iconico' && normalizeString(s.playerPseudo).replace(/_?icon$/, '') === normalizeString(picked.playerPseudo));
    if (srv && srv.imageUrl) picked.imageUrl = srv.imageUrl;
  }
  return picked;
}

// ===== Cromos EXTRA de borde negro (premios por actividad en Bellator) =====
const BLACK_EXTRA_DROP_PERCENT = 3;
const BLACK_EXTRAS = [
  {
    id: 'black-sekiro', name: 'SEKIRO',
    image: 'STICKERS/050b77ab14a86fcefa22a47fd495d290.jpg',
    note: 'First warrior to receive the Black Border. A whole season inside the arena, without losing a single battle.',
  },
  {
    id: 'black-bianca', name: 'BIANCA',
    image: 'STICKERS/475878211_122094566582766070_8045130554263902921_n.jpg',
    note: 'The first woman to earn it. Active since day one, immovable from the elite. Bellator chose her without hesitation.',
  },
  {
    id: 'black-eisengaard', name: 'EISENGAARD',
    image: 'STICKERS/735193523_122159961422413217_3074989910249570087_n.jpg',
    note: 'When everyone else gave up, Eisengaard kept going. The Black Border is not granted: it is earned with time and presence.',
  },
];

function buildBlackExtras() {
  return BLACK_EXTRAS.map((extra, index) => ({
    id: extra.id,
    series: '2026',
    groupKey: 'black-extras',
    groupLabel: 'Cromos Extra · Borde Negro',
    groupOrder: -500 + index,
    playerPseudo: 'BLACK EXTRAS',
    division: 'Cromos Extra',
    stickerType: index === 0 ? 'player' : 'char',
    variant: 'blackborder',
    displayName: extra.name,
    imageUrl: extra.image,
    rarity: 'blackborder',
    slotNumber: 800 + index,
    quantity: 0,
    collected: false,
    isNew: false,
    primaryColor: '#111',
    wins: 0, losses: 0, draws: 0, currentStreak: 0, rankingPoints: 0,
    clanName: 'Bellator',
    countryCode: '',
    isBlackExtra: true,
    blackNote: extra.note,
  }));
}

function blackExtrasWithCollection(serverStickers) {
  const coll = state.catalogMode === 'server' ? null : loadPreviewCollection();
  return buildBlackExtras().map((sticker) => {
    let quantity = 0;
    if (state.catalogMode === 'server' && Array.isArray(serverStickers)) {
      const cleanStatic = normalizeString(sticker.displayName);
      const matched = serverStickers.find(s => 
        safeText(s.specialType, '').toLowerCase() === 'extra' && 
        normalizeString(s.playerPseudo).replace(/_?extra$/, '') === cleanStatic
      );
      if (matched) {
        quantity = Number(matched.quantity || 0);
        sticker.id = matched.id; // UPDATE TO SERVER ID
        if (matched.imageUrl) sticker.imageUrl = matched.imageUrl;
      }
    } else if (coll) {
      quantity = Number(coll[sticker.id] || 0);
    }
    return { ...sticker, quantity, collected: quantity > 0, isNew: false };
  });
}

function pickBlackExtraDrop() {
  const coll = loadPreviewCollection();
  const all = buildBlackExtras();
  const unowned = all.filter((extra) => !(Number(coll[extra.id] || 0) > 0));

  const pool = unowned.length ? unowned : all;
  const picked = pool[randomIndex(pool.length)] || null;
  if (picked && Array.isArray(state.stickers)) {
    const srv = state.stickers.find(s => s.specialType === 'extra' && normalizeString(s.playerPseudo).replace(/_?extra$/, '') === normalizeString(picked.displayName));
    if (srv && srv.imageUrl) picked.imageUrl = srv.imageUrl;
  }
  return picked;
}

const FLIP_MS = 280;
const PACK_ANIMATION_MS = 920;
const STANDALONE_ALBUM_HOSTS = [
  'valhala-album.netlify.app',
  'valhala-album-2026.netlify.app',
];
const APP_ORIGIN = 'https://bellatorrpg.online';
const APP_ROUTE_MAP = {
  register: { app: '/registro', static: 'registro.html' },
  admission: { app: '/admision', static: 'admision.html' },
  competitors: { app: '/competidores', static: 'competidores.html' },
  ranking: { app: '/clasificacion', static: 'clasificacion.html' },
  rules: { app: '/reglamento', static: 'reglamento.html' },
  practice: { app: '/practica', static: 'practica.html' },
};

const DEFAULT_MISSION_CONFIG = {
  pack: { label: 'Reclama un sobre diario', total: 1 },
  pages: { label: 'Explora tres páginas del libro', total: 3 },
  newStickers: { label: 'Pega cinco cromos nuevos', total: 5 },
  cardCopy: 'Tu rutina diaria mezcla sobres, exploración del libro y crecimiento real de la colección.',
};

const DAILY_CHECKLIST_MISSIONS = [
  { id: 'daily-pack',    label: 'Abrir tu sobre del día',        icon: '📦', auto: 'pack' },
  { id: 'daily-pages',   label: 'Explorar el álbum',             sub: 'visita 3 páginas', icon: '📖', auto: 'pages' },
  { id: 'daily-clan',    label: 'Unirte o revisar tu clan',       sub: 'en Bellator', icon: '⚔️' },
  { id: 'daily-account', label: 'Completar tu perfil',            sub: 'foto, bio, división', icon: '👤' },
];

const WEEKLY_CHECKLIST_MISSIONS = [
  { id: 'weekly-battle', label: 'Buscar batalla en grupo',        sub: 'busca rival en la comunidad', icon: '🥊' },
  { id: 'weekly-react',  label: 'Reaccionar a todos los posts',   sub: 'del grupo Bellator', icon: '❤️' },
  { id: 'weekly-trade',  label: 'Publicar oferta de intercambio', sub: 'en el grupo de Bellator', icon: '🔄' },
];

function todayKey() { return new Date().toISOString().slice(0, 10); }
function thisWeekKey() {
  const d = new Date(); const start = new Date(d.getFullYear(), 0, 1);
  const w = Math.ceil(((d - start) / 86400000 + start.getDay() + 1) / 7);
  return `${d.getFullYear()}-W${String(w).padStart(2, '0')}`;
}
function loadDailyChecks(id) {
  try { return new Set(JSON.parse(localStorage.getItem(`valhala_daily_v1:${id}:${todayKey()}`) || '[]')); }
  catch { return new Set(); }
}
function saveDailyChecks(id, checks) {
  try { localStorage.setItem(`valhala_daily_v1:${id}:${todayKey()}`, JSON.stringify([...checks])); } catch {}
}
function loadWeeklyChecks(id) {
  try { return new Set(JSON.parse(localStorage.getItem(`valhala_weekly_v1:${id}:${thisWeekKey()}`) || '[]')); }
  catch { return new Set(); }
}
function saveWeeklyChecks(id, checks) {
  try { localStorage.setItem(`valhala_weekly_v1:${id}:${thisWeekKey()}`, JSON.stringify([...checks])); } catch {}
}

const SOUNDTRACK_OPTIONS = [
  { value: 'audio/bellator-intro.mp3', label: 'Bellator Intro' },
  { value: 'audio/goth-slowed.mp3', label: 'Goth Slowed' },
  { value: 'audio/let-go.mp3', label: 'Let Go' },
];

const state = {
  legacyPlayerKey: '',
  playerPseudo: '',
  session: null,
  sessionToken: '',
  albumViewer: null,
  baseStickers: [],
  stickers: [],
  pages: [],
  previewCollection: {},
  catalogMode: 'unknown',
  currentScene: 'intro',
  currentPage: 0,
  currentPack: [],
  pendingStickers: new Set(),
  revealIndex: 0,
  revealPhase: 'cards',
  overlayPool: [],
  overlayIndex: 0,
  tradeOfferSelection: new Set(),
  tradeWantSelection: new Set(),
  tradeWantFilter: '',
  tradeBoardFilter: 'open',
  tradePublishedRequests: [],
  tradeFeedback: { message: '', tone: '' },
  tradeTargets: [],
  tradeTargetPlayer: '',
  tradeTargetsLoading: false,
  missionConfig: { ...DEFAULT_MISSION_CONFIG },
  editingMissionKey: '',
  soundtrack: null,
  soundtrackReady: false,
  soundtrackPlaying: false,
  packAnimating: false,
  busy: false,
  loading: false,
};

let albumViewerRefreshTimer = null;

const refs = {
  body: document.body,
  introCopy: document.getElementById('intro-copy'),
  introProgressValue: document.getElementById('intro-progress-value'),
  introProgressCopy: document.getElementById('intro-progress-copy'),
  coverProgressCopy: document.getElementById('cover-progress-copy'),
  sceneTitle: document.getElementById('scene-title'),
  albumEyebrow: document.getElementById('album-eyebrow'),
  packQuota: document.getElementById('pack-quota'),
  identityHelp: document.getElementById('identity-help'),
  scenes: {
    intro: document.getElementById('scene-intro'),
    album: document.getElementById('scene-album'),
    reveal: document.getElementById('scene-reveal'),
  },
  status: document.getElementById('status-line'),
  pseudoInput: document.getElementById('player-pseudo-input'),
  keyInput: document.getElementById('player-key-input'),
  registerPseudoInput: document.getElementById('register-pseudo-input'),
  registerKeyInput: document.getElementById('register-key-input'),
  registerCountrySelect: document.getElementById('register-country-select'),
  saveKeyButton: document.getElementById('save-key-button'),
  registerFastButton: document.getElementById('register-fast-button'),
  clearKeyButton: document.getElementById('clear-key-button'),
  enterAlbumButton: document.getElementById('enter-album-button'),
  introPackButton: document.getElementById('intro-pack-button'),
  routeLinks: Array.from(document.querySelectorAll('[data-app-route]')),
  hubOpenAlbum: document.getElementById('hub-open-album'),
  hubOpenInventory: document.getElementById('hub-open-inventory'),
  inventoryModalBackdrop: document.getElementById('inventory-modal-backdrop'),
  inventoryModalClose: document.getElementById('inventory-modal-close'),
  invTabAll: document.getElementById('inv-tab-all'),
  invTabTrade: document.getElementById('inv-tab-trade'),
  invStats: document.getElementById('inv-stats'),
  invGridHost: document.getElementById('inventory-grid-host'),
  accessCardTitle: document.getElementById('access-card-title'),
  accessCardCopy: document.getElementById('access-card-copy'),
  accessOpenPanel: document.getElementById('access-open-panel'),
  hubLogout: document.getElementById('hub-logout'),
  accessRegisterLink: document.getElementById('access-register-link'),
  accessAdmissionLink: document.getElementById('access-admission-link'),
  tradeCardTitle: document.getElementById('trade-card-title'),
  tradeCardCopy: document.getElementById('trade-card-copy'),
  tradeCopyCount: document.getElementById('trade-copy-count'),
  tradeMissingCount: document.getElementById('trade-missing-count'),
  missionCardTitle: document.getElementById('mission-card-title'),
  missionCardCopy: document.getElementById('mission-card-copy'),
  missionPackLabel: document.getElementById('mission-pack-label'),
  missionPackRow: document.getElementById('mission-pack-row'),
  missionPackValue: document.getElementById('mission-pack-value'),
  missionPagesLabel: document.getElementById('mission-pages-label'),
  missionPagesRow: document.getElementById('mission-pages-row'),
  missionPagesValue: document.getElementById('mission-pages-value'),
  missionNewLabel: document.getElementById('mission-new-label'),
  missionNewRow: document.getElementById('mission-new-row'),
  missionNewValue: document.getElementById('mission-new-value'),
  missionPackEdit: document.getElementById('mission-pack-edit'),
  missionPagesEdit: document.getElementById('mission-pages-edit'),
  missionNewEdit: document.getElementById('mission-new-edit'),
  missionEditor: document.getElementById('mission-editor'),
  missionEditorLabel: document.getElementById('mission-editor-label'),
  missionEditorTotal: document.getElementById('mission-editor-total'),
  missionEditorCopy: document.getElementById('mission-editor-copy'),
  missionEditorSave: document.getElementById('mission-editor-save'),
  missionEditorCancel: document.getElementById('mission-editor-cancel'),
  missionEditorReset: document.getElementById('mission-editor-reset'),
  archiveCardTitle: document.getElementById('archive-card-title'),
  archiveCardCopy: document.getElementById('archive-card-copy'),
  soundtrackSelect: document.getElementById('soundtrack-select'),
  soundtrackToggle: document.getElementById('soundtrack-toggle'),
  soundtrackStop: document.getElementById('soundtrack-stop'),
  soundtrackMeta: document.getElementById('soundtrack-meta'),
  accederToggle: document.getElementById('acceder-toggle'),
  identityPanelWrap: document.getElementById('identity-panel-wrap'),
  missionBadgePack: document.getElementById('mission-badge-pack'),
  missionBadgePages: document.getElementById('mission-badge-pages'),
  missionBadgeNew: document.getElementById('mission-badge-new'),
  mnavIntro: document.getElementById('mnav-intro'),
  mnavPack: document.getElementById('mnav-pack'),
  mnavAlbum: document.getElementById('mnav-album'),
  mnavTrade: document.getElementById('mnav-trade'),
  backIntroButton: document.getElementById('back-intro-button'),
  albumPackButton: document.getElementById('album-pack-button'),
  albumHost: document.getElementById('album-host'),
  pagePrev: document.getElementById('page-prev'),
  pageNext: document.getElementById('page-next'),
  pagePill: document.getElementById('page-pill'),
  pagePillWrap: document.getElementById('page-pill-wrap'),
  pageJumpMenu: document.getElementById('page-jump-menu'),
  pageCaption: document.getElementById('page-caption'),
  packOpeningView: document.getElementById('pack-opening-view'),
  packSceneButton: document.getElementById('pack-scene-button'),
  packOpeningCopy: document.getElementById('pack-opening-copy'),
  packDailyPill: document.getElementById('pack-daily-pill'),
  packOpeningHint: document.getElementById('pack-opening-hint'),
  packFeatureImage: document.getElementById('pack-feature-image'),
  packFeatureFallback: document.getElementById('pack-feature-fallback'),
  packSachetSub: document.getElementById('pack-sachet-sub'),
  packSachetFooter: document.getElementById('pack-sachet-footer'),
  revealView: document.getElementById('reveal-view'),
  revealName: document.getElementById('reveal-name'),
  revealOwned: document.getElementById('reveal-owned'),
  revealCardHost: document.getElementById('reveal-card-host'),
  revealPrev: document.getElementById('reveal-prev'),
  revealNext: document.getElementById('reveal-next'),
  openAnotherButton: document.getElementById('open-another-button'),
  revealAlbumButton: document.getElementById('reveal-album-button'),
  revealPasteButton: document.getElementById('reveal-paste-button'),
  revealDownloadBtn: document.getElementById('reveal-download-btn'),
  packStrip: document.getElementById('pack-strip'),
  overlay: document.getElementById('overlay'),
  overlayClose: document.getElementById('overlay-close'),
  overlayCardHost: document.getElementById('overlay-card-host'),
  overlayPrev: document.getElementById('overlay-prev'),
  overlayNext: document.getElementById('overlay-next'),
  pendingTray: document.getElementById('pending-tray'),
  pendingCount: document.getElementById('pending-count'),
  hubOpenTrade: document.getElementById('hub-open-trade'),
  tradeModalBackdrop: document.getElementById('trade-modal-backdrop'),
  tradeModalClose: document.getElementById('trade-modal-close'),
  tradeTabOffer: document.getElementById('trade-tab-offer'),
  tradeTabImport: document.getElementById('trade-tab-import'),
  tradePanelOffer: document.getElementById('trade-panel-offer'),
  tradePanelImport: document.getElementById('trade-panel-import'),
  tradeDuplicateList: document.getElementById('trade-duplicate-list'),
  tradeWantList: document.getElementById('trade-want-list'),
  tradeWantFilter: document.getElementById('trade-want-filter'),
  tradeBuilderPlayer: document.getElementById('trade-builder-player'),
  tradeBuilderPending: document.getElementById('trade-builder-pending'),
  tradeBuilderOfferCount: document.getElementById('trade-builder-offer-count'),
  tradeBuilderWantCount: document.getElementById('trade-builder-want-count'),
  tradeTargetSelect: document.getElementById('trade-target-select'),
  tradeTargetHint: document.getElementById('trade-target-hint'),
  tradeBoardMeta: document.getElementById('trade-board-meta'),
  tradeBoardStatus: document.getElementById('trade-board-status'),
  tradeBoardCount: document.getElementById('trade-board-count'),
  tradeBoardHelpful: document.getElementById('trade-board-helpful'),
  tradeBoardMatch: document.getElementById('trade-board-match'),
  tradeBoardFilterOpen: document.getElementById('trade-board-filter-open'),
  tradeBoardFilterAll: document.getElementById('trade-board-filter-all'),
  tradeInventoryCopy: document.getElementById('trade-inventory-copy'),
  tradeCopyCodeButton: document.getElementById('trade-copy-code-button'),
  tradeOfferResult: document.getElementById('trade-offer-result'),
  tradeFeedbackBanner: document.getElementById('trade-feedback-banner'),
};

function setStatus(message, tone) {
  refs.status.textContent = message || '';
  refs.status.className = 'status-line' + (tone ? ' ' + tone : '');
}

function setTradeFeedback(message, tone) {
  state.tradeFeedback = {
    message: safeText(message, ''),
    tone: safeText(tone, ''),
  };
  if (!refs.tradeFeedbackBanner) return;
  if (!state.tradeFeedback.message) {
    refs.tradeFeedbackBanner.hidden = true;
    refs.tradeFeedbackBanner.textContent = '';
    refs.tradeFeedbackBanner.className = 'trade-feedback-banner';
    return;
  }
  refs.tradeFeedbackBanner.hidden = false;
  refs.tradeFeedbackBanner.textContent = state.tradeFeedback.message;
  refs.tradeFeedbackBanner.className = 'trade-feedback-banner' + (state.tradeFeedback.tone ? ' ' + state.tradeFeedback.tone : '');
}

function safeText(value, fallback) {
  const text = String(value || '').trim();
  return text || fallback;
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function slugSeries(value) {
  return safeText(value, 'Coleccion').replace(/\s+/g, ' ').trim();
}

function safeImageUrl(value) {
  const url = safeText(value, '');
  if (!url) return '';
  // Ya proxeada — evita doble envoltura si vuelve a pasar por aquí.
  if (/^https:\/\/images\.weserv\.nl\//i.test(url)) return url;
  if (/^https?:\/\//i.test(url)) {
    // Supabase Storage (nuestro propio bucket) carga directo y confiable.
    if (/(^|\.)supabase\.co\//i.test(url)) return url;
    // Imgur CDN funciona directo y el proxy está devolviendo 404 para estas URLs.
    if (/^https?:\/\/i\.imgur\.com\//i.test(url)) return url;
    // Netlify (nuestro host de stickers)
    if (/(^|\.)netlify\.app\//i.test(url)) return url;
    // El resto (pinimg, gstatic, wikia, imgur, animesher, etc.) se enruta por un
    // proxy de imágenes para esquivar ORB/hotlink/certificados inválidos del navegador.
    return 'https://images.weserv.nl/?url=' + encodeURIComponent(url.replace(/^https?:\/\//i, ''));
  }
  if (url.startsWith('/')) return url; // absoluto same-origin
  // Permitir assets locales relativos (ej: STICKERS/foo.webp) — bloquea data:/javascript: y traversal
  if (!url.includes('..') && (url.startsWith('STICKERS/') || /^[\w%][\w\-. /%()]*\.(webp|jpe?g|png|gif|avif)$/i.test(url))) return url;
  return '';
}

function simpleHash(value) {
  const input = String(value || '');
  let hash = 0;
  for (let index = 0; index < input.length; index += 1) {
    hash = ((hash << 5) - hash) + input.charCodeAt(index);
    hash |= 0;
  }
  return `fp_${Math.abs(hash).toString(16)}`;
}

async function generateAlbumFingerprint() {
  if (typeof window.generateDeviceFingerprint === 'function') {
    try {
      const value = await window.generateDeviceFingerprint();
      if (safeText(value, '')) return String(value);
    } catch (_) {
    }
  }
  const nav = window.navigator || {};
  const screenRef = window.screen || {};
  const seed = JSON.stringify({
    userAgent: nav.userAgent || '',
    language: nav.language || '',
    platform: nav.platform || '',
    vendor: nav.vendor || '',
    memory: nav.deviceMemory || 0,
    cores: nav.hardwareConcurrency || 0,
    width: screenRef.width || 0,
    height: screenRef.height || 0,
    depth: screenRef.colorDepth || 0,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
  });
  if (window.crypto && window.crypto.subtle && window.TextEncoder) {
    try {
      const encoded = new TextEncoder().encode(seed);
      const digest = await window.crypto.subtle.digest('SHA-256', encoded);
      return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
    } catch (_) {
    }
  }
  return simpleHash(seed);
}

function formatSlotLabel(slotNumber) {
  return `#${String(Number(slotNumber) || 0).padStart(3, '0')}`;
}

function readLegacyKeyFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return safeText(params.get('player_key'), '');
}

function readPseudoFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return safeText(params.get('pseudonimo') || params.get('pseudo'), '');
}

function loadStoredLegacyKey() {
  return safeText(localStorage.getItem(LEGACY_PLAYER_KEY_STORAGE_KEY), '');
}

function loadStoredPseudonimo() {
  return safeText(localStorage.getItem(PSEUDONIMO_STORAGE_KEY), '');
}

function normalizeAlbumSession(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const pseudonimo = safeText(raw.pseudonimo, '');
  if (!pseudonimo) return null;
  return {
    pseudonimo,
    division: safeText(raw.division, ''),
    avatarUrl: safeImageUrl(raw.avatar_url),
    local: Boolean(raw.local),
  };
}

function hasActiveSession() {
  return Boolean(state.session && safeText(state.session.pseudonimo, ''));
}

function loadStoredAlbumSessionToken() {
  return safeText(localStorage.getItem(ALBUM_SESSION_TOKEN_STORAGE_KEY), '');
}

function persistAlbumSessionToken(token) {
  const clean = safeText(token, '');
  state.sessionToken = clean;
  if (clean) localStorage.setItem(ALBUM_SESSION_TOKEN_STORAGE_KEY, clean);
  else localStorage.removeItem(ALBUM_SESSION_TOKEN_STORAGE_KEY);
}

function hasLegacyAccess() {
  return Boolean(safeText(state.legacyPlayerKey, ''));
}

function hasAlbumIdentity() {
  return hasActiveSession() || hasLegacyAccess();
}

function currentPlayerLabel() {
  return safeText(hasActiveSession() ? state.session.pseudonimo : state.playerPseudo, 'tu perfil');
}

function albumIdentityStorageKey() {
  if (hasActiveSession()) {
    return `session:${safeText(state.session.pseudonimo, 'jugador').toLowerCase()}`;
  }
  if (hasLegacyAccess()) {
    return `legacy:${state.legacyPlayerKey}`;
  }
  return 'public';
}

function resetTradeState() {
  state.tradeOfferSelection = new Set();
  state.tradeWantSelection = new Set();
  state.tradeWantFilter = '';
  state.tradeBoardFilter = 'open';
  state.tradePublishedRequests = [];
  state.tradeTargets = [];
  state.tradeTargetPlayer = '';
  state.tradeTargetsLoading = false;
}

async function restoreAlbumSession() {
  if (usesStaticRouteMap()) {
    resetTradeState();
    state.session = restoreLocalSession();
    if (hasActiveSession()) {
      state.playerPseudo = state.session.pseudonimo;
      state.legacyPlayerKey = '';
      localStorage.setItem(PSEUDONIMO_STORAGE_KEY, state.playerPseudo);
      localStorage.removeItem(LEGACY_PLAYER_KEY_STORAGE_KEY);
    }
    return;
  }

  try {
    const data = await fetchJson(albumApiUrl('/api/album/session'), { headers: requestHeaders(false) });
    resetTradeState();
    state.session = normalizeAlbumSession(data && data.session);
    if (hasActiveSession()) {
      state.playerPseudo = state.session.pseudonimo;
      state.legacyPlayerKey = '';
      localStorage.setItem(PSEUDONIMO_STORAGE_KEY, state.playerPseudo);
      localStorage.removeItem(LEGACY_PLAYER_KEY_STORAGE_KEY);
      localStorage.removeItem(LOCAL_SESSION_STORAGE_KEY);
    }
  } catch (error) {
    resetTradeState();
    state.session = usesStaticRouteMap() ? restoreLocalSession() : null;
    if (String(error && error.message || '').includes('album_session_invalid')) {
      persistAlbumSessionToken('');
    }
  }
}

// Sesión local (offline): permite exigir login aunque el backend de álbum no esté disponible.
function persistLocalSession(pseudonimo, countryCode) {
  try {
    localStorage.setItem(LOCAL_SESSION_STORAGE_KEY, JSON.stringify({
      pseudonimo: safeText(pseudonimo, ''),
      countryCode: safeText(countryCode, ''),
      local: true,
    }));
  } catch (_) {}
}

function restoreLocalSession() {
  try {
    const raw = localStorage.getItem(LOCAL_SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    const pseudonimo = safeText(parsed && parsed.pseudonimo, '');
    if (!pseudonimo) return null;
    return { pseudonimo, countryCode: safeText(parsed && parsed.countryCode, ''), local: true };
  } catch (_) {
    return null;
  }
}

function activateLocalSession(pseudonimo, countryCode) {
  const pseudo = safeText(pseudonimo, '');
  if (!pseudo) return;
  resetTradeState();
  state.session = { pseudonimo: pseudo, countryCode: safeText(countryCode, ''), local: true };
  state.playerPseudo = pseudo;
  state.legacyPlayerKey = '';
  state.previewCollection = {};
  state.pendingStickers = new Set();
  persistLocalSession(pseudo, countryCode);
  localStorage.setItem(PSEUDONIMO_STORAGE_KEY, pseudo);
  localStorage.removeItem(LEGACY_PLAYER_KEY_STORAGE_KEY);
}

function usesStaticRouteMap() {
  if (window.location.protocol === 'file:') return true;
  return /^(localhost|127\.0\.0\.1)$/i.test(window.location.hostname) && window.location.pathname.endsWith('.html');
}

function isStandaloneAlbumHost() {
  return STANDALONE_ALBUM_HOSTS.includes(window.location.hostname);
}

function shouldUseStandaloneAlbumMode() {
  return isStandaloneAlbumHost() || usesStaticRouteMap();
}

function rosterApiUrl() {
  return shouldUseStandaloneAlbumMode() ? `${APP_ORIGIN}/api/competidores` : '/api/competidores';
}

function resolveAppRoute(routeKey) {
  const route = APP_ROUTE_MAP[routeKey];
  if (!route) return '#';
  if (isStandaloneAlbumHost()) return `${APP_ORIGIN}${route.app}`;
  return usesStaticRouteMap() ? route.static : route.app;
}

function hydrateRouteLinks() {
  refs.routeLinks.forEach((link) => {
    const routeKey = link.dataset.appRoute;
    const target = resolveAppRoute(routeKey);
    link.setAttribute('href', target);
  });
}

function loadPreviewCollection() {
  try {
    const parsed = JSON.parse(localStorage.getItem(previewCollectionStorageKey()) || '{}');
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch (_) {
    return {};
  }
}

function savePreviewCollection(collection) {
  state.previewCollection = collection;
  localStorage.setItem(previewCollectionStorageKey(), JSON.stringify(collection));
}

function loadMissionConfig() {
  try {
    const parsed = JSON.parse(localStorage.getItem(MISSION_CONFIG_STORAGE_KEY) || '{}');
    return {
      pack: {
        label: safeText(parsed.pack && parsed.pack.label, DEFAULT_MISSION_CONFIG.pack.label),
        total: Math.max(1, Number(parsed.pack && parsed.pack.total) || DEFAULT_MISSION_CONFIG.pack.total),
      },
      pages: {
        label: safeText(parsed.pages && parsed.pages.label, DEFAULT_MISSION_CONFIG.pages.label),
        total: Math.max(1, Number(parsed.pages && parsed.pages.total) || DEFAULT_MISSION_CONFIG.pages.total),
      },
      newStickers: {
        label: safeText(parsed.newStickers && parsed.newStickers.label, DEFAULT_MISSION_CONFIG.newStickers.label),
        total: Math.max(1, Number(parsed.newStickers && parsed.newStickers.total) || DEFAULT_MISSION_CONFIG.newStickers.total),
      },
      cardCopy: safeText(parsed.cardCopy, DEFAULT_MISSION_CONFIG.cardCopy),
    };
  } catch (_) {
    return { ...DEFAULT_MISSION_CONFIG };
  }
}

function remoteAlbumApiBase() {
  return isStandaloneAlbumHost() ? APP_ORIGIN : '';
}

function shouldUseRemoteAlbumApi() {
  return isStandaloneAlbumHost() || !usesStaticRouteMap();
}

function albumApiUrl(path) {
  return `${remoteAlbumApiBase()}${path}`;
}

function sanitizeMissionConfig(config) {
  const source = config && typeof config === 'object' ? config : {};
  return {
    pack: {
      label: safeText(source.pack && source.pack.label, DEFAULT_MISSION_CONFIG.pack.label),
      total: Math.max(1, Number(source.pack && source.pack.total) || DEFAULT_MISSION_CONFIG.pack.total),
    },
    pages: {
      label: safeText(source.pages && source.pages.label, DEFAULT_MISSION_CONFIG.pages.label),
      total: Math.max(1, Number(source.pages && source.pages.total) || DEFAULT_MISSION_CONFIG.pages.total),
    },
    newStickers: {
      label: safeText(source.newStickers && source.newStickers.label, DEFAULT_MISSION_CONFIG.newStickers.label),
      total: Math.max(1, Number(source.newStickers && source.newStickers.total) || DEFAULT_MISSION_CONFIG.newStickers.total),
    },
    cardCopy: safeText(source.cardCopy, DEFAULT_MISSION_CONFIG.cardCopy),
  };
}

async function loadRemoteMissionConfig() {
  if (!shouldUseRemoteAlbumApi()) return false;
  try {
    const data = await fetchJson(albumApiUrl('/api/album/config'));
    state.missionConfig = sanitizeMissionConfig(data);
    return true;
  } catch (_) {
    return false;
  }
}

async function loadAlbumViewerSummary() {
  state.albumViewer = null;
  if (!shouldUseRemoteAlbumApi() || !hasActiveSession()) return null;
  try {
    const data = await fetchJson(albumApiUrl('/api/album/me'));
    state.albumViewer = {
      authenticated: Boolean(data && data.authenticated),
      bonusPacks: Math.max(0, Number(data && data.bonus_packs) || 0),
      dailyPacks: {
        count: Math.max(0, Number(data && data.daily_packs && data.daily_packs.count) || 0),
        remaining: Math.max(0, Number(data && data.daily_packs && data.daily_packs.remaining) || 0),
        resetAt: safeText(data && data.daily_packs && data.daily_packs.reset_at, ''),
      },
    };
    return state.albumViewer;
  } catch (_) {
    state.albumViewer = null;
    return null;
  }
}

async function refreshAlbumViewerSummary(options = {}) {
  const { silent = true } = options;
  if (!shouldUseRemoteAlbumApi() || !hasActiveSession()) {
    state.albumViewer = null;
    updateHeaderSummary();
    return null;
  }
  const viewer = await loadAlbumViewerSummary();
  updateHeaderSummary();
  if (!silent && viewer) {
    setStatus(`Sobres extra sincronizados para ${currentPlayerLabel()}.`, 'success');
  }
  return viewer;
}

function startAlbumViewerAutoRefresh() {
  if (albumViewerRefreshTimer) return;
  albumViewerRefreshTimer = window.setInterval(() => {
    if (document.hidden || state.busy || state.loading || !hasActiveSession()) return;
    refreshAlbumViewerSummary({ silent: true }).catch(() => {});
  }, 30000);
}

function bonusPackCount() {
  return Math.max(0, Number(state.albumViewer && state.albumViewer.bonusPacks) || 0);
}

function canUseBonusPack() {
  return hasActiveSession() && bonusPackCount() > 0 && shouldUseRemoteAlbumApi();
}

function canOpenAnyPack() {
  return dailyPackSummary().remaining > 0 || canUseBonusPack();
}

function saveMissionConfig() {
  localStorage.setItem(MISSION_CONFIG_STORAGE_KEY, JSON.stringify(state.missionConfig));
}

function loadSoundtrackSelection() {
  const stored = safeText(localStorage.getItem(SOUNDTRACK_STORAGE_KEY), SOUNDTRACK_OPTIONS[0].value);
  return SOUNDTRACK_OPTIONS.some((item) => item.value === stored) ? stored : SOUNDTRACK_OPTIONS[0].value;
}

function saveSoundtrackSelection(value) {
  localStorage.setItem(SOUNDTRACK_STORAGE_KEY, value);
}

function packQuotaStorageKey() {
  return `${DAILY_PACK_STORAGE_KEY}:${albumIdentityStorageKey()}`;
}

function localPackWindowMs() {
  return 24 * 60 * 60 * 1000;
}

function localDayToken() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function loadDailyPackQuota() {
  const windowStart = Date.now() - localPackWindowMs();
  try {
    const parsed = JSON.parse(localStorage.getItem(packQuotaStorageKey()) || '{}');
    const rawOpenings = parsed && Array.isArray(parsed.openedAt) ? parsed.openedAt : [];
    const openings = rawOpenings
      .map((value) => safeText(value, ''))
      .filter(Boolean)
      .map((value) => new Date(value).getTime())
      .filter((value) => Number.isFinite(value) && value >= windowStart)
      .sort((left, right) => left - right);
    const resetIndex = openings.length >= DAILY_FREE_PACK_LIMIT ? openings.length - DAILY_FREE_PACK_LIMIT : -1;
    return {
      day: localDayToken(),
      count: openings.length,
      openedAt: openings.map((value) => new Date(value).toISOString()),
      resetAt: resetIndex >= 0 ? new Date(openings[resetIndex] + localPackWindowMs()).toISOString() : '',
    };
  } catch (_) {
  }
  return { day: localDayToken(), count: 0, openedAt: [], resetAt: '' };
}

function saveDailyPackQuota(quota) {
  const openings = Array.isArray(quota && quota.openedAt) ? quota.openedAt.map((value) => safeText(value, '')).filter(Boolean) : [];
  localStorage.setItem(packQuotaStorageKey(), JSON.stringify({ openedAt: openings }));
}

function claimDailyPackQuota() {
  const quota = loadDailyPackQuota();
  if (quota.count >= DAILY_FREE_PACK_LIMIT) {
    return { ...quota, remaining: 0, claimed: false };
    }
  quota.openedAt = Array.isArray(quota.openedAt) ? quota.openedAt.slice() : [];
  quota.openedAt.push(new Date().toISOString());
  saveDailyPackQuota(quota);
  const nextQuota = loadDailyPackQuota();
  return {
    ...nextQuota,
    remaining: Math.max(0, DAILY_FREE_PACK_LIMIT - nextQuota.count),
    claimed: true,
  };
}

function activityStorageKey() {
  return `${DAILY_ACTIVITY_STORAGE_KEY}:${albumIdentityStorageKey()}`;
}

function loadDailyActivity() {
  const day = localDayToken();
  try {
    const parsed = JSON.parse(localStorage.getItem(activityStorageKey()) || '{}');
    if (parsed && parsed.day === day) {
      return {
        day,
        visitedPages: Array.isArray(parsed.visitedPages) ? [...new Set(parsed.visitedPages.map((item) => safeText(item, '')).filter(Boolean))] : [],
        newStickers: Math.max(0, Number(parsed.newStickers || 0)),
      };
    }
  } catch (_) {
  }
  return { day, visitedPages: [], newStickers: 0 };
}

function saveDailyActivity(activity) {
  localStorage.setItem(activityStorageKey(), JSON.stringify(activity));
}

function recordVisitedPage(index) {
  const page = state.pages[index];
  if (!page) return false;
  const marker = `${safeText(page.groupKey, 'page')}::${page.pageNumber}`;
  const activity = loadDailyActivity();
  if (activity.visitedPages.includes(marker)) return false;
  activity.visitedPages.push(marker);
  saveDailyActivity(activity);
  return true;
}

function recordNewStickers(count) {
  const increment = Math.max(0, Number(count || 0));
  if (!increment) return;
  const activity = loadDailyActivity();
  activity.newStickers += increment;
  saveDailyActivity(activity);
}

function dailyPackSummary() {
  if (shouldUseRemoteAlbumApi() && hasActiveSession() && state.albumViewer && state.albumViewer.dailyPacks) {
    return {
      day: localDayToken(),
      count: Math.max(0, Number(state.albumViewer.dailyPacks.count) || 0),
      remaining: Math.max(0, Number(state.albumViewer.dailyPacks.remaining) || 0),
      resetAt: safeText(state.albumViewer.dailyPacks.resetAt, ''),
    };
  }
  const quota = loadDailyPackQuota();
  return {
    ...quota,
    remaining: Math.max(0, DAILY_FREE_PACK_LIMIT - quota.count),
    resetAt: '',
  };
}

function normalizeDivisionKey(value) {
  const division = safeText(value, '').toLowerCase();
  return division.includes('ciudad') ? 'ciudad' : 'universal';
}

function divisionLabel(value) {
  return normalizeDivisionKey(value) === 'ciudad' ? 'Ciudad' : 'Universal';
}

function calcRosterRarity(player) {
  const wins = Number(player.wins || 0);
  const rankingPoints = Number(player.ranking_points || 0);
  const currentStreak = Number(player.current_streak || 0);
  if (wins >= 10 || rankingPoints >= 100) return 'legendario';
  if (wins >= 5 || currentStreak >= 3) return 'epico';
  if (wins >= 2) return 'raro';
  return 'comun';
}

function upgradeRosterRarity(baseRarity) {
  const index = ROSTER_RARITY_ORDER[baseRarity] ?? 0;
  return ROSTER_RARITY_UP[Math.min(index + 1, ROSTER_RARITY_UP.length - 1)];
}

function rarityLabel(rarity) {
  const labels = {
    comun: 'Comun',
    raro: 'Raro',
    epico: 'Epico',
    legendario: 'Legendario',
    dorado: 'Dorado',
    iconico: '✦ Icónico',
    extra: '◆ Extra',
    diamante: '◈ Diamante',
    blackborder: '✦ Borde Negro',
    esmeralda: '🟢 Esmeralda',
  };
  return labels[rarity] || 'Comun';
}

function buildPreviewCatalogFromRoster(players) {
  const orderedPlayers = (Array.isArray(players) ? players : [])
    .slice()
    .sort((left, right) => {
      const leftDivision = DIVISION_ORDER[normalizeDivisionKey(left.division)] ?? 99;
      const rightDivision = DIVISION_ORDER[normalizeDivisionKey(right.division)] ?? 99;
      if (leftDivision !== rightDivision) return leftDivision - rightDivision;
      const leftPoints = Number(left.ranking_points || 0);
      const rightPoints = Number(right.ranking_points || 0);
      if (leftPoints !== rightPoints) return rightPoints - leftPoints;
      const leftWins = Number(left.wins || 0);
      const rightWins = Number(right.wins || 0);
      if (leftWins !== rightWins) return rightWins - leftWins;
      return safeText(left.pseudonimo, '').localeCompare(safeText(right.pseudonimo, ''), 'es');
    });

  const divisionCounters = { universal: 1, ciudad: 1 };
  const stickers = [];

  orderedPlayers.forEach((player) => {
    // Skip players with no character slots defined or explicitly excluded
    const pseudo = safeText(player.pseudonimo, '');
    const hasAnyChar = [1, 2, 3].some((i) => safeText(player[`top_char_${i}`], '') !== '');
    if (ALBUM_EXCLUDED.has(pseudo.toLowerCase()) || !hasAnyChar) return;
    const divisionKey = normalizeDivisionKey(player.division);
    const groupLabel = divisionLabel(player.division);
    const baseRarity = calcRosterRarity(player);
    const sharedMeta = {
      series: '2026',
      group_key: divisionKey,
      group_label: groupLabel,
      group_order: DIVISION_ORDER[divisionKey] ?? 99,
      player_pseudo: safeText(player.pseudonimo, 'Sin nombre'),
      division: groupLabel,
      primary_color: safeText(player.primary_color, ''),
      wins: Number(player.wins || 0),
      losses: Number(player.losses || 0),
      draws: Number(player.draws || 0),
      current_streak: Number(player.current_streak || 0),
      ranking_points: Number(player.ranking_points || 0),
      clan_name: safeText(player.clan_name, ''),
      country_code: safeText(player.country_code, ''),
    };

    const pseudoLower = pseudo.toLowerCase();
    const overrideKey = Object.keys(AVATAR_OVERRIDES).find((k) => pseudoLower.startsWith(k));
    const entries = [{
      type: 'player',
      displayName: safeText(player.pseudonimo, 'Sin nombre'),
      imageUrl: (overrideKey && AVATAR_OVERRIDES[overrideKey]) || safeImageUrl(player.avatar_url),
      rarity: baseRarity,
    }];

    [1, 2, 3].forEach((index) => {
      const name = safeText(player[`top_char_${index}`], '');
      const imageUrl = safeImageUrl(player[`top_char_${index}_image`]);
      if (!name && !imageUrl) return;
      entries.push({
        type: `char_${index}`,
        displayName: name || `Personaje ${index}`,
        imageUrl,
        rarity: upgradeRosterRarity(baseRarity),
      });
    });

    entries.forEach((entry) => {
      const slotNumber = divisionCounters[divisionKey]++;
      stickers.push(normalizeSticker({
        ...sharedMeta,
        id: `${divisionKey}-${String(slotNumber).padStart(3, '0')}-${entry.type}`,
        sticker_type: entry.type,
        variant: 'normal',
        display_name: entry.displayName,
        image_url: entry.imageUrl,
        rarity: entry.rarity,
        slot_number: slotNumber,
      }));
    });
  });

  return stickers;
}

function normalizeSticker(raw) {
  const collected = Boolean(raw.collected || raw.quantity > 0);
  return {
    id: safeText(raw.id, ''),
    series: slugSeries(raw.series || raw.division || 'Coleccion'),
    groupKey: safeText(raw.group_key || raw.series || raw.division || 'Coleccion', 'Coleccion'),
    groupLabel: safeText(raw.group_label || raw.series || raw.division || 'Coleccion', 'Coleccion'),
    groupOrder: Number(raw.group_order || 0),
    playerPseudo: safeText(raw.player_pseudo, ''),
    division: safeText(raw.division, ''),
    stickerType: safeText(raw.sticker_type, 'competidor'),
    variant: safeText(raw.variant, ''),
    specialType: safeText(raw.special_type || raw.specialType, '').toLowerCase(),
    displayName: safeText(raw.display_name || raw.player_pseudo, 'Sin nombre'),
    imageUrl: safeImageUrl(raw.image_url),
    get rarity() {
      const stype = safeText(raw.special_type || raw.specialType, '').toLowerCase();
      if (stype === 'diamante') return 'diamante';
      if (stype === 'iconico') return 'iconico';
      if (stype === 'extra') return 'blackborder';
      if (stype === 'esmeralda') return 'esmeralda';
      return safeText(raw.rarity, 'comun').toLowerCase();
    },
    slotNumber: Number(raw.slot_number || 0),
    quantity: Number(raw.quantity || 0),
    collected,
    isNew: Boolean(raw.is_new),
    primaryColor: safeText(raw.primary_color, ''),
    wins: Number(raw.wins || 0),
    losses: Number(raw.losses || 0),
    draws: Number(raw.draws || 0),
    currentStreak: Number(raw.current_streak || 0),
    rankingPoints: Number(raw.ranking_points || 0),
    clanName: safeText(raw.clan_name, ''),
    countryCode: safeText(raw.country_code, ''),
  };
}

function groupedPages(stickers) {
  const rosterPages = [];
  const universalPages = [];
  const ciudadPages = [];
  const playerOrder = [];
  const seenPlayers = new Set();

  stickers
    .slice()
    .sort((a, b) => (a.groupOrder - b.groupOrder) || (a.slotNumber - b.slotNumber))
    .forEach((sticker) => {
      const key = `${sticker.groupKey}__${sticker.playerPseudo}`;
      if (!seenPlayers.has(key)) {
        seenPlayers.add(key);
        playerOrder.push({
          groupKey: sticker.groupKey,
          groupLabel: sticker.groupLabel,
          playerPseudo: sticker.playerPseudo,
        });
      }
    });

  playerOrder.forEach(({ groupKey, groupLabel, playerPseudo }) => {
    const playerStickers = stickers
      .filter((sticker) => sticker.groupKey === groupKey && sticker.playerPseudo === playerPseudo)
      .sort((a, b) => a.slotNumber - b.slotNumber);

    const playerSticker = playerStickers.find((sticker) => sticker.stickerType === 'player') || playerStickers[0] || null;
    const charStickers = playerStickers.filter((sticker) => sticker.stickerType !== 'player').slice(0, 3);
    const collectibleStickers = [playerSticker, ...charStickers].filter(Boolean).slice(0, 4);

    const page = {
      name: playerPseudo || groupLabel,
      rawName: playerPseudo || groupLabel,
      pageNumber: 0,
      groupLabel,
      groupKey,
      playerSticker,
      charStickers,
      collectibleStickers,
      items: playerStickers,
      isIconic: Boolean(playerSticker && playerSticker.isIconic),
      isBlackExtras: groupKey === 'black-extras',
      isDiamond: Boolean(playerSticker && safeText(playerSticker.specialType, '').toLowerCase() === 'diamante'),
      collectedCount: playerStickers.filter((sticker) => sticker.collected).length,
      totalCount: playerStickers.length,
    };

    if (page.isIconic || page.isBlackExtras || page.isDiamond) {
      rosterPages.push(page);
      return;
    }
    if ((groupKey || '').toLowerCase() === 'ciudad') {
      ciudadPages.push(page);
      return;
    }
    universalPages.push(page);
  });

  const pages = [];
  pages.push(...universalPages);
  pages.push({
    name: 'Cómo funciona Bellator',
    rawName: 'Cómo funciona Bellator',
    pageNumber: 0,
    groupLabel: 'Guía de Bellator',
    groupKey: 'album-overview',
    playerSticker: null,
    charStickers: [],
    collectibleStickers: [],
    items: [],
    isIconic: false,
    isAlbumOverview: true,
    collectedCount: 0,
    totalCount: 0,
  });
  pages.push(...ciudadPages);
  pages.push({
    name: 'Coming Soon',
    rawName: 'Coming Soon',
    pageNumber: 0,
    groupLabel: 'Próximamente',
    groupKey: 'coming-soon',
    playerSticker: null,
    charStickers: [],
    collectibleStickers: [],
    items: [],
    isIconic: false,
    isComingSoon: true,
    collectedCount: 0,
    totalCount: 0,
  });

  const iconicPages = rosterPages.filter((page) => page.isIconic);
  const blackExtraPages = rosterPages.filter((page) => page.isBlackExtras);
  // Diamond pages removed — diamonds exist in drops/inventory only
  pages.push(...blackExtraPages, ...iconicPages);

  pages.forEach((page, index) => { page.pageNumber = index + 1; });
  return pages;
}

function applyPreviewCollection(baseStickers, collection) {
  return baseStickers.map((sticker) => {
    const quantity = Number(collection[sticker.id] || 0);
    return {
      ...sticker,
      quantity,
      collected: quantity > 0,
      isNew: false,
    };
  });
}

function randomIndex(max) {
  if (max <= 0) return 0;
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    const values = new Uint32Array(1);
    globalThis.crypto.getRandomValues(values);
    return values[0] % max;
  }
  return Math.floor(Math.random() * max);
}

function countryFlag(code) {
  if (!code || code.length < 2) return '';
  const up = code.toUpperCase().slice(0, 2);
  if (!/^[A-Z]{2}$/.test(up)) return '';
  return [...up].map((c) => String.fromCodePoint(0x1F1E0 + c.charCodeAt(0) - 65)).join('');
}

function countryFlagImg(code) {
  if (!code || code.length < 2) return '';
  const up = code.toUpperCase().slice(0, 2);
  if (!/^[A-Z]{2}$/.test(up)) return '';
  return `https://flagcdn.com/w40/${up.toLowerCase()}.png`;
}

function weightedPreviewRarity() {
  const distribution = [
    { rarity: 'comun', weight: 65 },
    { rarity: 'raro', weight: 24 },
    { rarity: 'epico', weight: 8 },
    { rarity: 'legendario', weight: 3 },
  ];
  const total = distribution.reduce((sum, item) => sum + item.weight, 0);
  let cursor = randomIndex(total);
  for (const item of distribution) {
    if (cursor < item.weight) return item.rarity;
    cursor -= item.weight;
  }
  return distribution[distribution.length - 1].rarity;
}

function totalCollectedCount() {
  return state.stickers.filter((sticker) => sticker.collected).length;
}

function duplicateSummary() {
  const duplicateTypes = state.stickers.filter((sticker) => sticker.quantity > 1).length;
  const duplicateCopies = state.stickers.reduce((sum, sticker) => sum + Math.max(0, sticker.quantity - 1), 0);
  const missing = state.stickers.filter((sticker) => !sticker.collected).length;
  return { duplicateTypes, duplicateCopies, missing };
}

function inventorySummary() {
  const total = state.stickers.length;
  const owned = state.stickers.filter((sticker) => sticker.quantity > 0).length;
  const pending = state.pendingStickers.size;
  const duplicates = duplicateSummary();
  return {
    total,
    owned,
    pending,
    availableToOffer: duplicates.duplicateCopies,
    missing: duplicates.missing,
  };
}

function isRosterAlbumPage(page) {
  return Boolean(page) && !page.isAlbumOverview && !page.isIconInfo && !page.isBlackExtras && !page.isIconic && !page.isComingSoon && !page.isDiamond;
}

function rosterPageCount() {
  return state.pages.filter((page) => isRosterAlbumPage(page)).length;
}

function rosterSpecialPageCount() {
  return Math.max(0, state.pages.length - rosterPageCount());
}

function rosterPageIndex(page) {
  if (!isRosterAlbumPage(page)) return 0;
  let index = 0;
  for (const currentPage of state.pages) {
    if (isRosterAlbumPage(currentPage)) index += 1;
    if (currentPage === page) return index;
  }
  return index;
}

function loadTradeRequests() {
  return Array.isArray(state.tradePublishedRequests)
    ? state.tradePublishedRequests.filter((item) => item && typeof item === 'object')
    : [];
}

/*
function normalizedPseudoMatchKey(value) {
  const text = safeText(value, '').normalize('NFKD').toLowerCase();
  let out = '';
  for (const char of text) {
    if (/[ -]/.test(char) && /[a-z0-9]/.test(char)) {
      out += char;
      continue;
    }
    if (/[\s_-]/.test(char)) continue;
    if (/[00-6f]/.test(char)) continue;
    if (/\p{Letter}|\p{Number}/u.test(char)) {
      out += char;
    }
  }
  return out;
}

*/

function normalizedPseudoMatchKey(value) {
  const text = safeText(value, '').normalize('NFKD').toLowerCase();
  let out = '';
  for (const char of text) {
    if (/[\u0000-\u007f]/.test(char) && /[a-z0-9]/.test(char)) {
      out += char;
      continue;
    }
    if (/[\s_-]/.test(char)) continue;
    if (/[\u0300-\u036f]/.test(char)) continue;
    if (/\p{Letter}|\p{Number}/u.test(char)) {
      out += char;
    }
  }
  return out;
}

function sameTradePlayer(left, right) {
  const leftValue = normalizedPseudoMatchKey(left);
  const rightValue = normalizedPseudoMatchKey(right);
  return Boolean(leftValue) && leftValue === rightValue;
}

function saveTradeRequests(requests) {
  state.tradePublishedRequests = Array.isArray(requests) ? requests : [];
}

function removeExistingRequestForIdentity(requests, identityKey) {
  return requests.filter((request) => safeText(request.identityKey, '') !== identityKey);
}

async function fetchTradeBoard() {
  if (!hasActiveSession() || !shouldUseRemoteAlbumApi()) {
    state.tradePublishedRequests = [];
    return [];
  }
  const data = await fetchJson(albumApiUrl('/api/album/trades'), { headers: requestHeaders(false) });
  state.tradePublishedRequests = Array.isArray(data) ? data : [];
  return state.tradePublishedRequests;
}

async function fetchTradeTargets() {
  if (!hasActiveSession() || !shouldUseRemoteAlbumApi()) {
    state.tradeTargetsLoading = false;
    state.tradeTargets = [];
    state.tradeTargetPlayer = '';
    return [];
  }
  state.tradeTargetsLoading = true;
  try {
    const data = await fetchJson(albumApiUrl('/api/album/users'), { headers: requestHeaders(false) });
    const targets = Array.isArray(data)
      ? data.map((item) => safeText(item && item.pseudonimo, '')).filter(Boolean)
      : [];
    state.tradeTargets = targets;
    const selected = targets.find((pseudo) => sameTradePlayer(pseudo, state.tradeTargetPlayer));
    state.tradeTargetPlayer = selected || targets[0] || '';
    return state.tradeTargets;
  } catch (error) {
    state.tradeTargets = [];
    state.tradeTargetPlayer = '';
    throw error;
  } finally {
    state.tradeTargetsLoading = false;
  }
}

function buildTradeRequestPayload() {
  const offer = tradeOfferInventory().filter((sticker) => state.tradeOfferSelection.has(sticker.id));
  const want = tradeMissingInventory().filter((sticker) => state.tradeWantSelection.has(sticker.id));
  const targetPlayer = state.tradeTargets.find((pseudo) => sameTradePlayer(pseudo, state.tradeTargetPlayer)) || safeText(state.tradeTargetPlayer, '');
  if (!hasActiveSession() || !shouldUseRemoteAlbumApi() || !targetPlayer || (!offer.length && !want.length)) return null;
  return {
    id: `trade_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    identityKey: albumIdentityStorageKey(),
    player: currentPlayerLabel(),
    targetPlayer,
    local: Boolean(state.session && state.session.local),
    createdAt: new Date().toISOString(),
    status: 'open',
    pendingCount: state.pendingStickers.size,
    offer: offer.map((sticker) => ({
      id: sticker.id,
      name: sticker.displayName,
      group: sticker.groupLabel,
      rarity: sticker.rarity,
      extra: sticker.quantity - 1,
      pending: state.pendingStickers.has(sticker.id),
    })),
    want: want.map((sticker) => ({
      id: sticker.id,
      name: sticker.displayName,
      group: sticker.groupLabel,
      rarity: sticker.rarity,
    })),
  };
}

function missionSnapshot() {
  const packSummary = dailyPackSummary();
  const activity = loadDailyActivity();
  const config = state.missionConfig;
  const missions = {
    pack: {
      label: config.pack.label,
      current: Math.min(packSummary.count, config.pack.total),
      total: config.pack.total,
      done: packSummary.count >= config.pack.total,
    },
    pages: {
      label: config.pages.label,
      current: Math.min(activity.visitedPages.length, config.pages.total),
      total: config.pages.total,
      done: activity.visitedPages.length >= config.pages.total,
    },
    newStickers: {
      label: config.newStickers.label,
      current: Math.min(activity.newStickers, config.newStickers.total),
      total: config.newStickers.total,
      done: activity.newStickers >= config.newStickers.total,
    },
  };
  const completeCount = Object.values(missions).filter((mission) => mission.done).length;
  return { ...missions, completeCount };
}

function renderMissionRow(row, valueNode, mission) {
  row.classList.toggle('done', mission.done);
  valueNode.textContent = mission.done ? 'Completa' : `${mission.current} / ${mission.total}`;
}

function formatDailyPackCopy(summary) {
  const bonus = bonusPackCount();
  if (summary.remaining > 0) {
    return bonus > 0
      ? `Sobres gratis: ${summary.remaining} / ${DAILY_FREE_PACK_LIMIT} disponibles cada 24 horas · Sobres extra del admin: ${bonus}`
      : `Sobres gratis: ${summary.remaining} / ${DAILY_FREE_PACK_LIMIT} disponibles cada 24 horas`;
  }
  return bonus > 0
    ? `Sobres gratis agotados por 24 horas · Sobres extra del admin: ${bonus}`
    : 'Sobres gratis agotados por 24 horas';
}

// ── Pack countdown ────────────────────────────────────────────
let packCountdownTimer = null;

function formatCountdown(ms) {
  if (ms <= 0) return '00:00:00';
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
}

function updatePackCountdown() {
  if (!refs.packQuota) return;
  const summary = dailyPackSummary();
  if (summary.remaining > 0 || canUseBonusPack()) {
    if (packCountdownTimer) { clearInterval(packCountdownTimer); packCountdownTimer = null; }
    refs.packQuota.textContent = formatDailyPackCopy(summary);
    refs.packQuota.classList.remove('pack-quota-countdown');
    return;
  }
  const resetAt = safeText(summary.resetAt, '');
  const resetTime = resetAt ? new Date(resetAt).getTime() : NaN;
  const msLeft = Number.isFinite(resetTime) ? (resetTime - Date.now()) : NaN;
  if (!Number.isFinite(msLeft)) {
    refs.packQuota.textContent = formatDailyPackCopy(summary);
    refs.packQuota.classList.remove('pack-quota-countdown');
    return;
  }
  if (msLeft <= 0) {
    if (packCountdownTimer) { clearInterval(packCountdownTimer); packCountdownTimer = null; }
    updateHeaderSummary();
    return;
  }
  refs.packQuota.textContent = `⏱ Próximo sobre gratis en ${formatCountdown(msLeft)}`;
  refs.packQuota.classList.add('pack-quota-countdown');
}

function startPackCountdown() {
  if (packCountdownTimer) { clearInterval(packCountdownTimer); packCountdownTimer = null; }
  updatePackCountdown();
  if (dailyPackSummary().remaining > 0 || canUseBonusPack()) return;
  packCountdownTimer = setInterval(updatePackCountdown, 1000);
}

function renderMissionsCard() {
  const el = document.getElementById('mission-sections');
  if (!el) return;

  const identity = albumIdentityStorageKey();
  const dailyDone = loadDailyChecks(identity);
  const weeklyDone = loadWeeklyChecks(identity);

  // Auto-sync from existing activity tracking
  const snap = missionSnapshot();
  if (snap.pack && snap.pack.done) dailyDone.add('daily-pack');
  if (snap.pages && snap.pages.done) dailyDone.add('daily-pages');

  const mk = (m, type, done) => {
    const isDone = done.has(m.id);
    return `<div class="mission-check-row ${type}${isDone ? ' done' : ''}" data-mission-id="${m.id}" data-mission-type="${type}" role="button" tabindex="${isDone ? -1 : 0}" aria-pressed="${isDone}">
      <div class="mcr-tick">${isDone ? '✓' : ''}</div>
      <div class="mcr-copy">
        <span class="mcr-label"><span class="mcr-emoji">${m.icon}</span> ${escapeHtml(m.label)}</span>
        ${m.sub ? `<span class="mcr-sub">${escapeHtml(m.sub)}</span>` : ''}
      </div>
    </div>`;
  };

  el.innerHTML =
    `<div class="mission-section">`
    + `<div class="mission-section-label"><span class="mcr-emoji">⚡</span> Diarias</div>`
    + DAILY_CHECKLIST_MISSIONS.map((m) => mk(m, 'daily', dailyDone)).join('')
    + `</div>`
    + `<div class="mission-section">`
    + `<div class="mission-section-label"><span class="mcr-emoji">🗓</span> Semanales <span class="mission-admin-note">· confirmar con admin</span></div>`
    + WEEKLY_CHECKLIST_MISSIONS.map((m) => mk(m, 'weekly', weeklyDone)).join('')
    + `</div>`;

  const total = DAILY_CHECKLIST_MISSIONS.length + WEEKLY_CHECKLIST_MISSIONS.length;
  const totalDone = dailyDone.size + weeklyDone.size;
  const titleEl = document.getElementById('mission-card-title');
  if (titleEl) titleEl.textContent = `${Math.min(totalDone, total)} / ${total} completadas`;
  if (refs.missionCardCopy) refs.missionCardCopy.textContent = state.missionConfig.cardCopy;

  el.querySelectorAll('.mission-check-row:not(.done)').forEach((row) => {
    row.addEventListener('click', () => {
      const id = row.dataset.missionId;
      const type = row.dataset.missionType;
      const ident = albumIdentityStorageKey();
      const lbl = row.querySelector('.mcr-label');
      const label = lbl ? lbl.textContent.trim() : id;
      const reward = type === 'weekly' ? 3 : 1;
      const sobreText = reward === 1 ? '1 sobre' : `${reward} sobres`;
      if (type === 'daily') {
        const c = loadDailyChecks(ident); c.add(id); saveDailyChecks(ident, c);
      } else {
        const c = loadWeeklyChecks(ident); c.add(id); saveWeeklyChecks(ident, c);
      }
      alert(`✅ Misión completada: "${label}"\n\n🎁 Recompensa: ${sobreText}\n\n⚠️ Avísale a un administrador y muéstrale esta pantalla para que te entregue tu recompensa.`);
      setStatus(`✅ "${label}" marcada · recompensa ${sobreText}. Avísale a un admin para reclamarla.`, 'success');
      renderMissionsCard();
    });
    row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); row.click(); } });
  });
}

function updateHeaderSummary() {
  const total = state.baseStickers ? state.baseStickers.length : 0;
  const collected = state.baseStickers ? state.baseStickers.filter((sticker) => sticker.collected).length : 0;
  const percent = total ? Math.round((collected / total) * 100) : 0;
  const rosterProfiles = rosterPageCount();
  const specialPages = rosterSpecialPageCount();
  const packSummary = dailyPackSummary();
  const duplicates = duplicateSummary();
  const missions = missionSnapshot();
  const playerLabel = currentPlayerLabel();
  const isLocalProfile = Boolean(hasActiveSession() && state.session && state.session.local);
  const modeLabel = state.catalogMode === 'preview'
    ? isLocalProfile ? 'perfil local' : 'roster activo'
    : hasActiveSession()
      ? 'Bellator real'
      : hasLegacyAccess()
        ? 'acceso legado'
        : 'invitado';

  refs.introProgressValue.textContent = state.loading ? '...' : `${collected} / ${total}`;
  refs.introProgressCopy.textContent = state.loading
    ? 'Cargando roster y catalogo...'
    : total
      ? `${percent}% completado · ${rosterProfiles} peleadores · ${modeLabel}`
      : 'Libro sin datos cargados';
  refs.coverProgressCopy.textContent = state.loading
    ? 'Sincronizando libro...'
    : total
      ? `${rosterProfiles} peleadores${specialPages ? ` + ${specialPages} especiales` : ''} · ${modeLabel}`
      : 'Esperando catalogo';
  refs.albumEyebrow.textContent = total
    ? `Coleccion ${modeLabel} · ${percent}%`
    : `Coleccion ${modeLabel}`;

  refs.introCopy.textContent = state.catalogMode === 'preview'
    ? isLocalProfile
      ? `Tu perfil local Bellator está activo como ${playerLabel}. Tu colección ya es privada para este perfil y no comparte cromos con tus pruebas de invitado.`
      : 'Tu libro ya corre sobre el roster activo de Bellator. Mientras termina de desplegarse la sincronizacion total del album, aqui ya puedes seguir tu coleccion, sobres diarios y repetidas reales.'
    : hasActiveSession()
      ? `Tu sesion Bellator esta activa como ${playerLabel}. Esta portada ya funciona como centro de acceso para coleccion, archivo, admision y progreso diario del album.`
      : hasLegacyAccess()
        ? 'El album detecto una clave heredada de sincronizacion. Sigue funcionando por compatibilidad, pero el acceso real ahora entra con pseudonimo + clave Bellator.'
        : 'Entra al libro en modo invitado o vincula tu acceso Bellator desde Registro para guardar la coleccion, ordenar repetidas y volver con una identidad real.';

  refs.identityHelp.textContent = hasActiveSession()
    ? isLocalProfile
      ? `Perfil local activo como ${playerLabel}. Tus cromos demo ya no se mezclan con este perfil; cuando el backend del álbum responda, este acceso podrá migrarse.`
      : `Sesion Bellator activa como ${playerLabel}. Si tu coleccion remota responde, se sincroniza sola; si no, el album sigue usando el roster activo mientras termina el despliegue.`
    : hasLegacyAccess()
      ? 'Estas usando una clave heredada de sincronizacion. Sigue siendo compatible, pero el acceso real del album ahora se valida con pseudonimo + clave personal.'
      : 'Bellator hoy usa pseudonimo + clave personal. Registrate, valida admision y vuelve aqui para activar tu coleccion real.';

  refs.packQuota.textContent = formatDailyPackCopy(packSummary);
  refs.packDailyPill.textContent = `Gratis usados: ${packSummary.count} / ${DAILY_FREE_PACK_LIMIT} en 24 horas · Extras del admin: ${bonusPackCount()}`;

  const packLocked = state.loading || state.busy || !canOpenAnyPack();
  refs.introPackButton.textContent = canOpenAnyPack() ? 'Abrir sobre Bellator' : 'Sin sobres disponibles';
  refs.openAnotherButton.textContent = canOpenAnyPack() ? 'Abrir otro' : 'Sin sobres disponibles';
  refs.albumPackButton.disabled = packLocked;
  refs.introPackButton.disabled = packLocked;
  refs.openAnotherButton.disabled = packLocked;

  if (refs.missionBadgePack) refs.missionBadgePack.innerHTML = `📦 <span>${escapeHtml(state.missionConfig.pack.label)}</span>`;
  if (refs.missionBadgePages) refs.missionBadgePages.innerHTML = `📖 <span>${escapeHtml(state.missionConfig.pages.total)} paginas</span>`;
  if (refs.missionBadgeNew) refs.missionBadgeNew.innerHTML = `⭐ <span>${escapeHtml(state.missionConfig.newStickers.total)} cromos</span>`;

  refs.accessCardTitle.textContent = hasActiveSession() ? `${isLocalProfile ? 'Perfil local Bellator' : 'Sesion Bellator'}: ${playerLabel}` : hasLegacyAccess() ? 'Clave heredada conectada' : 'Registro + clave Bellator';
  refs.accessCardCopy.textContent = hasActiveSession()
    ? isLocalProfile
      ? 'Tu identidad Bellator ya está aislada en este perfil local. Tus cromos de pruebas públicas no cuentan aquí.'
      : 'Tu identidad Bellator ya esta conectada. Desde aqui entras al libro, abres sobres diarios y saltas al ecosistema real sin pasar por una vista aparte.'
    : hasLegacyAccess()
      ? 'Tienes una clave heredada conectada para compatibilidad. Si quieres login real, vuelve a entrar con pseudonimo + clave Bellator.'
      : 'No hay correo ni password social aqui: el acceso real nace en Registro, se valida en Admision y vuelve al album con tu clave personal.';

  if (refs.accessOpenPanel) {
    refs.accessOpenPanel.hidden = false;
    refs.accessOpenPanel.textContent = hasAlbumIdentity() ? 'Gestionar acceso' : 'Entrar / registrarme';
  }
  if (refs.hubLogout) refs.hubLogout.hidden = !hasAlbumIdentity();
  if (refs.accessRegisterLink) refs.accessRegisterLink.hidden = hasAlbumIdentity();
  if (refs.accessAdmissionLink) refs.accessAdmissionLink.hidden = hasAlbumIdentity();

  refs.tradeCardTitle.textContent = duplicates.duplicateCopies > 0
    ? `${duplicates.duplicateCopies} repetida${duplicates.duplicateCopies > 1 ? 's' : ''} lista${duplicates.duplicateCopies > 1 ? 's' : ''} para enviar`
    : hasActiveSession() ? 'Elige jugador y manda solicitud' : 'Inicia sesión para negociar';
  refs.tradeCardCopy.textContent = hasActiveSession()
    ? duplicates.duplicateCopies > 0
      ? `Inventario claro: ${inventorySummary().owned}/${inventorySummary().total} cromos en tu poder, ${inventorySummary().pending} pendientes de pegar y ${duplicates.duplicateCopies} copias extra listas para mandar en solicitudes directas.`
      : `Ya puedes pedir faltantes con tu perfil. Elige a qué jugador se lo quieres mandar y la solicitud le caerá a ese perfil, no a un muro genérico.`
    : 'El mercado solo se abre con sesión activa. Inicia sesión para ver tu inventario real, bloquear el modo invitado y publicar solicitudes de intercambio.';
  refs.tradeCopyCount.textContent = String(duplicates.duplicateCopies);
  refs.tradeMissingCount.textContent = String(duplicates.missing);
  if (refs.tradeInventoryCopy) {
    const inventory = inventorySummary();
    refs.tradeInventoryCopy.textContent = hasActiveSession()
      ? `Ahora mismo tienes ${inventory.owned} cromos en tu poder, ${inventory.pending} pendientes de pegar, ${inventory.availableToOffer} copias extra para ofrecer y ${inventory.missing} faltantes para pedir directamente.`
      : 'Tu inventario completo se desbloquea al iniciar sesión: ahí verás qué ya posees, qué sigue pendiente y qué realmente puedes negociar.';
  }

  refs.archiveCardTitle.textContent = total ? `${rosterProfiles} perfiles en archivo` : 'Circuito Bellator';
  refs.archiveCardCopy.textContent = total
    ? 'Registro, archivo y combate ya estan conectados: entra al archivo de competidores para abrir perfiles e historial, y usa clasificacion o practica para seguir el circuito.'
    : 'El hub del album comparte base con el archivo Bellator. Desde aqui saltas a registro, competidores, clasificacion y practica sin salir del sistema.';

  renderMissionsCard();
}

function openMissionEditor(key) {
  setStatus('Las misiones oficiales del álbum ahora se editan desde el panel admin.', 'error');
  closeMissionEditor();
}

function closeMissionEditor() {
  state.editingMissionKey = '';
  refs.missionEditor.hidden = true;
  updateHeaderSummary();
}

function saveMissionEditor() {
  setStatus('Las misiones oficiales del álbum ahora se editan desde el panel admin.', 'error');
  closeMissionEditor();
}

function resetMissionEditor() {
  setStatus('Las misiones oficiales del álbum ahora se editan desde el panel admin.', 'error');
  closeMissionEditor();
}

function ensureSoundtrack() {
  if (state.soundtrack) return state.soundtrack;
  state.soundtrack = new Audio('audio/bellator-intro.mp3');
  state.soundtrack.loop = true;
  state.soundtrack.volume = 0.55;
  state.soundtrack.addEventListener('play', () => {
    state.soundtrackPlaying = true;
    refs.soundtrackToggle.textContent = '⏸';
    refs.soundtrackToggle.classList.add('playing');
  });
  state.soundtrack.addEventListener('pause', () => {
    state.soundtrackPlaying = false;
    refs.soundtrackToggle.textContent = '♫';
    refs.soundtrackToggle.classList.remove('playing');
  });
  state.soundtrackReady = true;
  return state.soundtrack;
}

function applySoundtrackSelection(value) {
  const track = ensureSoundtrack();
  if (track.src && track.src.endsWith(value)) return;
  const wasPlaying = state.soundtrackPlaying;
  track.pause();
  track.src = value;
  track.load();
  saveSoundtrackSelection(value);
  refs.soundtrackMeta.textContent = `Pista seleccionada: ${refs.soundtrackSelect.options[refs.soundtrackSelect.selectedIndex].text}`;
  if (wasPlaying) {
    track.play().catch(() => {
      refs.soundtrackMeta.textContent = 'El navegador bloqueó el autoplay. Pulsa reproducir.';
    });
  }
}

function toggleSoundtrack() {
  const track = ensureSoundtrack();
  if (!track.paused) {
    track.pause();
  } else {
    track.play().catch(() => {});
  }
}

function stopSoundtrack() {
  const track = ensureSoundtrack();
  track.pause();
  track.currentTime = 0;
  refs.soundtrackMeta.textContent = 'Soundtrack detenido.';
}

function syncRevealPhase() {
  const packActive = state.currentScene === 'reveal' && state.revealPhase === 'pack';
  const revealActive = state.currentScene === 'reveal' && state.revealPhase === 'cards';
  refs.packOpeningView.classList.toggle('active', packActive);
  refs.revealView.classList.toggle('active', revealActive);
}

function syncBodyScene() {
  if (state.currentScene === 'intro') {
    refs.body.dataset.scene = 'intro';
    return;
  }
  if (state.currentScene === 'reveal') {
    refs.body.dataset.scene = 'reveal';
    return;
  }
  refs.body.dataset.scene = 'album';
}

function pickPackFeatureSticker() {
  return state.currentPack
    .slice()
    .sort((left, right) => {
      const rightValue = ROSTER_RARITY_ORDER[right.rarity] ?? 0;
      const leftValue = ROSTER_RARITY_ORDER[left.rarity] ?? 0;
      if (rightValue !== leftValue) return rightValue - leftValue;
      if (Boolean(right.imageUrl) !== Boolean(left.imageUrl)) return right.imageUrl ? 1 : -1;
      return left.slotNumber - right.slotNumber;
    })[0] || null;
}

function renderPackOpening() {
  const summary = dailyPackSummary();
  const featured = pickPackFeatureSticker();
  const division = featured ? divisionLabel(featured.groupLabel || featured.groupKey) : 'Universal';
  const usingBonus = summary.remaining <= 0 && bonusPackCount() > 0;

  refs.packSceneButton.classList.remove('tearing');
  refs.packOpeningHint.textContent = 'Toca el sobre para abrirlo';
  refs.packOpeningCopy.textContent = usingBonus
    ? `Tus sobres gratis de las ultimas 24 horas ya se agotaron. Vas a usar 1 sobre extra del admin para revelar ${state.currentPack.length} laminas.`
    : `Sobre gratis ${summary.count} de ${DAILY_FREE_PACK_LIMIT} reclamado en las ultimas 24 horas. Rompe el sello para revelar ${state.currentPack.length} laminas.`;
  refs.packSachetSub.textContent = featured ? `${featured.groupLabel} · Official Stickers` : 'Official Stickers';
  refs.packSachetFooter.textContent = `${state.currentPack.length} laminas oficiales · ${division}`;

  if (featured && featured.imageUrl) {
    refs.packFeatureImage.src = featured.imageUrl;
    refs.packFeatureImage.alt = featured.displayName;
    refs.packFeatureImage.style.display = 'block';
    refs.packFeatureFallback.style.display = 'none';
  } else {
    refs.packFeatureImage.removeAttribute('src');
    refs.packFeatureImage.style.display = 'none';
    refs.packFeatureFallback.style.display = 'grid';
    refs.packFeatureFallback.textContent = featured ? safeText(featured.displayName, 'B').charAt(0).toUpperCase() : 'B';
  }
}

function startPackRevealFlow() {
  state.revealIndex = 0;
  state.revealPhase = 'pack';
  state.packAnimating = false;
  renderPackOpening();
  switchScene('reveal');
}

function playPackOpening() {
  if (state.packAnimating || state.revealPhase !== 'pack' || !state.currentPack.length) return;
  state.packAnimating = true;
  refs.packSceneButton.classList.add('tearing');
  refs.packOpeningHint.textContent = 'Abriendo sobre...';

  setTimeout(() => {
    state.packAnimating = false;
    state.revealPhase = 'cards';
    renderReveal();
    syncRevealPhase();
  }, PACK_ANIMATION_MS);
}

function stickerCardMarkup(sticker) {
  const specialType = safeText(sticker && sticker.specialType, '').toLowerCase();
  if (specialType === 'iconico') {
    return iconicCardMarkup(sticker, { locked: false });
  }
  if (specialType === 'extra') {
    return blackExtraCardMarkup(sticker, { locked: false });
  }
  if (specialType === 'diamante') {
    return legendaryDiamondCardMarkup(sticker);
  }
  const displayName = escapeHtml(sticker.displayName);
  const series = escapeHtml(sticker.series);
  const metaName = escapeHtml(safeText(sticker.playerPseudo, safeText(sticker.stickerType, 'Cromo')));
  const imageUrl = escapeHtml(sticker.imageUrl);
  const isBB = sticker.rarity === 'blackborder' || sticker.variant === 'blackborder';
  const initials = escapeHtml(safeText(sticker.displayName, '').replace(/[^\w\s]/g, '').split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('') || '?');
  const photo = sticker.imageUrl
    ? `<div class="sticker-photo"><img src="${imageUrl}" alt="${displayName}" onerror="const parent=this.parentElement;if(!parent)return;parent.classList.add('fallback');const d=document.createElement('div');d.className='slot-initials';d.textContent='${initials}';this.replaceWith(d)"></div>`
    : `<div class="sticker-photo fallback"><div class="slot-initials">${initials}</div></div>`;
  const flagRawCode = sticker.countryCode ? String(sticker.countryCode).toUpperCase().slice(0, 2) : '';
  const flagImgSrc = flagRawCode ? countryFlagImg(flagRawCode) : '';
  const flagEmojiFb = flagRawCode ? countryFlag(flagRawCode) : '';
  const flagHtml = flagRawCode
    ? `<div class="sticker-flag-img" title="${escapeHtml(flagRawCode)}"><img src="${flagImgSrc}" alt="${escapeHtml(flagRawCode)}" loading="lazy" onerror="this.style.display='none';if(this.nextElementSibling)this.nextElementSibling.style.display='flex'"><span style="display:none">${escapeHtml(flagEmojiFb || flagRawCode)}</span></div>`
    : '';
  const holoHtml = isBB ? '<div class="slot-holo" aria-hidden="true"></div>' : '';
  const bbTag = isBB ? '<div class="bb-tag">✦ Borde Negro</div>' : '';
  const wins = sticker.wins || 0;
  const losses = sticker.losses || 0;
  const rank = sticker.rankingPoints || 0;
  const statsHtml = (wins || losses) ? `<div class="sticker-stats-bar"><span class="ssb-w">${wins}V</span><span class="ssb-l">${losses}D</span>${rank ? `<span class="ssb-r">★${rank}</span>` : ''}</div>` : '';
  const divisionShort = escapeHtml(safeText(sticker.division || sticker.groupLabel, ''));
  const clanText = sticker.clanName ? ` · ${escapeHtml(sticker.clanName)}` : '';

  return `
    <div class="sticker-card rarity-${escapeHtml(sticker.rarity)}" data-series="${series}">
      <div class="sticker-rarity"></div>
      ${holoHtml}
      ${bbTag}
      ${photo}
      ${flagHtml}
      ${statsHtml}
      <div class="flag-tag">${escapeHtml(formatSlotLabel(sticker.slotNumber))}</div>
      ${sticker.isNew ? '<div class="new-tag">Nuevo</div>' : ''}
      ${sticker.quantity > 1 ? `<div class="qty-tag">x${sticker.quantity}</div>` : ''}
      <div class="sticker-footer">
        <div class="name-pill">${displayName}</div>
        <div class="meta-pill">${escapeHtml(rarityLabel(sticker.rarity))} · ${divisionShort}${clanText}</div>
      </div>
    </div>`;
}

function renderReveal() {
  const sticker = state.currentPack[state.revealIndex];
  if (!sticker) return;
  refs.revealName.textContent = sticker.displayName;
  
  const stype = safeText(sticker.specialType, '').toLowerCase();
  if (stype === 'iconico') {
    refs.revealCardHost.innerHTML = iconicCardMarkup(sticker, { locked: false });
  } else if (stype === 'diamante') {
    refs.revealCardHost.innerHTML = legendaryDiamondCardMarkup(sticker);
  } else if (stype === 'esmeralda') {
    refs.revealCardHost.innerHTML = emeraldCardMarkup(sticker);
  } else if (stype === 'extra') {
    refs.revealCardHost.innerHTML = blackExtraCardMarkup(sticker, { locked: false });
  } else {
    refs.revealCardHost.innerHTML = stickerCardMarkup(sticker);
  }

  // Badge NUEVA / REPETIDA
  if (refs.revealOwned) {
    const isNew = Boolean(sticker.isNew);
    const qty = Number(sticker.quantity || 0);
    refs.revealOwned.hidden = false;
    refs.revealOwned.classList.toggle('is-new', isNew);
    refs.revealOwned.classList.toggle('is-repeat', !isNew);
    refs.revealOwned.textContent = isNew
      ? '✦ ¡NUEVA! · no la tenías'
      : `↺ Ya la tienes${qty > 1 ? ` · x${qty}` : ''}`;
  }

  // Epic entrance animation per rarity
  const specialType = safeText(sticker.specialType, '').toLowerCase();
  const rarity = (specialType === 'iconico' || specialType === 'diamante' || specialType === 'esmeralda') 
    ? (specialType === 'esmeralda' ? 'esmeralda' : 'iconico') : safeText(sticker.rarity, 'comun');
  refs.revealCardHost.classList.remove('cr-common','cr-raro','cr-epico','cr-legendario','cr-iconico','cr-esmeralda');
  void refs.revealCardHost.offsetWidth; // force reflow to restart animation
  const crClassMap = { comun:'cr-common', raro:'cr-raro', epico:'cr-epico', legendario:'cr-legendario', iconico:'cr-iconico', esmeralda:'cr-esmeralda' };
  refs.revealCardHost.classList.add(crClassMap[rarity] || 'cr-common');

  // Flash burst overlay
  const flashEl = document.createElement('div');
  flashEl.className = `cr-flash-overlay ${rarity}`;
  document.body.appendChild(flashEl);
  flashEl.addEventListener('animationend', () => flashEl.remove(), { once: true });

  // Confetti celebration for ultra rares
  const isDorado = sticker.variant === 'dorado' || safeText(sticker.rarity, '').toLowerCase() === 'legendario';
  if (window.confetti && (stype === 'diamante' || stype === 'esmeralda' || stype === 'iconico' || stype === 'extra' || isDorado)) {
    const duration = 3000;
    const end = Date.now() + duration;
    const colors = stype === 'esmeralda' ? ['#00ff80', '#00ff66', '#ffffff'] : 
                   stype === 'diamante' ? ['#b8f0ff', '#ffffff', '#ffd966'] : 
                   stype === 'iconico' ? ['#ffd966', '#ffb700', '#ffffff'] : stype === 'extra' ? ['#ffffff', '#888888', '#000000'] : isDorado ? ['#ffd700', '#ffb300', '#ffffff'] : ['#ffffff'];
    
    (function frame() {
      confetti({
        particleCount: 5,
        angle: 60,
        spread: 55,
        origin: { x: 0, y: 0.8 },
        colors: colors,
        zIndex: 9999
      });
      confetti({
        particleCount: 5,
        angle: 120,
        spread: 55,
        origin: { x: 1, y: 0.8 },
        colors: colors,
        zIndex: 9999
      });
      if (Date.now() < end) requestAnimationFrame(frame);
    }());
  }

  refs.revealPrev.disabled = state.revealIndex === 0;
  refs.revealNext.disabled = state.revealIndex === state.currentPack.length - 1;
  refs.packStrip.innerHTML = state.currentPack.map((_, index) => (
    `<div class="pack-dot${index === state.revealIndex ? ' active' : ''}"></div>`
  )).join('');
  syncRevealPhase();
}

function spreadColors(playerSticker) {
  const raw = playerSticker && playerSticker.primaryColor ? playerSticker.primaryColor : '';
  let main = '#1556a0';
  if (/^#[0-9a-f]{6}$/i.test(raw)) {
    main = raw;
  } else if (playerSticker && playerSticker.groupKey === 'ciudad') {
    main = '#c21466';
  }

  const r = parseInt(main.slice(1, 3), 16);
  const g = parseInt(main.slice(3, 5), 16);
  const b = parseInt(main.slice(5, 7), 16);
  const accent2 = `#${Math.min(255, Math.round(255 - r * 0.34)).toString(16).padStart(2, '0')}${Math.min(255, Math.round(g * 0.45 + 18)).toString(16).padStart(2, '0')}${Math.min(255, Math.round(b * 0.36 + 34)).toString(16).padStart(2, '0')}`;
  const accent = (r > 200 && g > 180) ? '#ffffff' : '#ffe14c';
  return { main, accent2, accent };
}

// ─────────────────────────────────────────────────────────────────────
// Tarjeta legendaria diamante + showcase de intro
// ─────────────────────────────────────────────────────────────────────

function legendaryDiamondCardMarkup(legend) {
  const name = escapeHtml(safeText(legend.displayName || legend.name, 'Leyenda'));
  const img = escapeHtml(safeImageUrl(legend.imageUrl || legend.image) || '');
  const rating = escapeHtml(String(legend.legendRating || legend.rating || 109));
  const position = escapeHtml(safeText(legend.legendPosition || legend.position, 'PRIME'));
  const photo = img
    ? `<div class="dc-photo"><img src="${img}" alt="${name}" loading="lazy" onerror="const p=this.parentElement;if(!p)return;p.classList.add('fallback');this.remove()"></div>`
    : '<div class="dc-photo fallback"></div>';
  return `
    <div class="diamond-legendary-card">
      <div class="dc-prism-bg" aria-hidden="true"></div>
      <div class="dc-shine" aria-hidden="true"></div>
      <div class="dc-sparkles" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i></div>
      <div class="dc-rating"><strong>${rating}</strong><span>${position}</span></div>
      <div class="dc-tier">◈ DIAMANTE</div>
      ${photo}
      <div class="dc-overlay" aria-hidden="true"></div>
      <div class="dc-plate">
        <div class="dc-name">${name}</div>
        <div class="dc-sub">negro · oro · diamante</div>
      </div>
    </div>`;
}

function emeraldCardMarkup(legend) {
  const name = escapeHtml(safeText(legend.displayName || legend.display_name || legend.name, 'Leyenda'));
  const img = escapeHtml(safeImageUrl(legend.imageUrl || legend.image_url || legend.image) || '');
  const rating = escapeHtml(String(legend.legendRating || legend.rating || 111));
  const position = escapeHtml(safeText(legend.legendPosition || legend.position, 'ESMERALDA'));
  const photo = img
    ? `<div class="dc-photo"><img src="${img}" alt="${name}" loading="lazy" onerror="const p=this.parentElement;if(!p)return;p.classList.add('fallback');this.remove()"></div>`
    : '<div class="dc-photo fallback"></div>';
  return `
    <div class="diamond-legendary-card emerald">
      <div class="dc-prism-bg" aria-hidden="true"></div>
      <div class="dc-shine" aria-hidden="true"></div>
      <div class="dc-sparkles" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i></div>
      <div class="dc-rating"><strong>${rating}</strong><span>${position}</span></div>
      <div class="dc-tier">🟢 ESMERALDA</div>
      ${photo}
      <div class="dc-overlay" aria-hidden="true"></div>
      <div class="dc-plate">
        <div class="dc-name">${name}</div>
        <div class="dc-sub">verde · poder · deseos</div>
      </div>
    </div>`;
}

function renderIntroShowcaseCards() {
  const bandetIconicData = {
    displayName: 'BANDET',
    name: 'BANDET',
    legendRating: 109,
    legendPosition: 'PRIME',
    legendAccent: '#c8102e',
    legendAccent2: '#3a0a12',
    imageUrl: 'STICKERS/images (2).jpg',
    legacyLabel: 'Orochi Legacy',
    countryCode: '',
  };
  const bandetBlackData = {
    displayName: 'BANDET',
    name: 'BANDET',
    imageUrl: 'STICKERS/images (2).jpg',
    blackNote: 'El primero. El talento puro de Orochi.',
  };
  const bandetDiamondData = {
    name: 'BANDET',
    rating: 109,
    position: 'PRIME',
    image: 'STICKERS/images (2).jpg',
  };
  const bandetEmeraldData = {
    displayName: 'BANDET',
    name: 'BANDET',
    legendRating: 109,
    legendPosition: 'PRIME',
    imageUrl: 'STICKERS/images (2).jpg',
  };

  const iconicHost = document.getElementById('intro-card-iconic');
  if (iconicHost) iconicHost.innerHTML = iconicCardMarkup(bandetIconicData, { locked: false });

  const blackHost = document.getElementById('intro-card-black');
  if (blackHost) blackHost.innerHTML = blackExtraCardMarkup(bandetBlackData, { locked: false });

  const diamondHost = document.getElementById('intro-card-diamond');
  if (diamondHost) diamondHost.innerHTML = legendaryDiamondCardMarkup(bandetDiamondData);

  const emeraldHost = document.getElementById('intro-card-emerald');
  if (emeraldHost) emeraldHost.innerHTML = emeraldCardMarkup(bandetEmeraldData);
}

function renderBookState(title, copy, variant) {
  refs.pagePill.textContent = 'Album';
  refs.pageCaption.textContent = variant === 'loading' ? 'Preparando libro' : 'Sin datos';
  refs.pagePrev.style.visibility = 'hidden';
  refs.pageNext.style.visibility = 'hidden';
  refs.pagePrev.disabled = true;
  refs.pageNext.disabled = true;
  refs.albumHost.innerHTML = `
    <div class="book-frame">
      <div class="book-state">
        <div class="book-state-card${variant === 'loading' ? ' loading' : ''}">
          <h2>${escapeHtml(title)}</h2>
          <p>${escapeHtml(copy)}</p>
        </div>
      </div>
    </div>`;
}

function renderAlbumSlot(sticker, fallbackLabel) {
  if (!sticker) {
    return `
      <button class="slot" type="button" disabled>
        <div class="slot-placeholder">
          <div class="cap">${escapeHtml(fallbackLabel)}</div>
          <div class="ghost">+</div>
          <div class="plate">Por descubrir</div>
        </div>
      </button>`;
  }

  const slotLabel = formatSlotLabel(sticker.slotNumber);
  const displayName = escapeHtml(sticker.displayName);
  const series = escapeHtml(sticker.series);
  const isBB = sticker.rarity === 'blackborder' || sticker.variant === 'blackborder';

  if (!sticker.collected) {
    return `
      <button class="slot" type="button" disabled>
        <div class="slot-placeholder">
          <div class="cap">${series}</div>
          <div class="ghost">+</div>
          <div class="plate">${displayName}<br>${slotLabel}</div>
        </div>
      </button>`;
  }

  const isPending = state.pendingStickers.has(sticker.id);
  const initials = displayName.replace(/[^\w\s]/g, '').split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('') || '?';
  const photo = sticker.imageUrl
    ? `<div class="slot-photo"><img src="${escapeHtml(sticker.imageUrl)}" alt="${displayName}" onerror="const p=this.parentElement;if(!p)return;p.classList.add('fallback');const d=document.createElement('div');d.className='slot-initials';d.textContent='${escapeHtml(initials)}';p.appendChild(d);this.remove()"></div>`
    : `<div class="slot-photo fallback"><div class="slot-initials">${escapeHtml(initials)}</div></div>`;
  const flagCode = sticker.countryCode ? String(sticker.countryCode).toUpperCase().slice(0, 2) : '';
  const flagImgSrc = flagCode ? countryFlagImg(flagCode) : '';
  const flagHtml = flagCode
    ? `<div class="slot-flag-banner">${flagImgSrc ? `<img class="sfb-img" src="${flagImgSrc}" alt="${escapeHtml(flagCode)}" loading="lazy" onerror="this.style.display='none'">` : ''}<span class="sfb-code">${escapeHtml(flagCode)}</span></div>`
    : '';
  const holoHtml = isBB ? '<div class="slot-holo" aria-hidden="true"></div>' : '';
  const rarityLabelText = escapeHtml(rarityLabel(sticker.rarity));

  const pasteOverlay = isPending ? `
    <div class="slot-paste-overlay" data-paste-id="${escapeHtml(sticker.id)}">
      <div class="paste-icon">+</div>
      <div class="paste-label">Pegar</div>
    </div>` : '';

  return `
    <button class="slot" type="button" data-sticker-id="${escapeHtml(sticker.id)}"${isPending ? ' data-pending="true"' : ''}>
      <div class="slot-card rarity-${escapeHtml(sticker.rarity)}" data-series="${series}">
        <div class="slot-shine" aria-hidden="true"></div>
        <div class="slot-number">${slotLabel}</div>
        ${sticker.quantity > 1 ? `<div class="slot-quantity">x${sticker.quantity}</div>` : ''}
        ${holoHtml}
        ${photo}
        ${flagHtml}
        <div class="slot-rarity-tag">${rarityLabelText}</div>
        <div class="slot-footer">${displayName}</div>
      </div>
      ${pasteOverlay}
    </button>`;
}

function iconicCardMarkup(sticker, opts) {
  const options = opts || {};
  const locked = Boolean(options.locked);
  const name = escapeHtml(safeText(sticker.displayName || sticker.display_name || sticker.name, 'Leyenda'));
  const rating = escapeHtml(String(sticker.legendRating || sticker.rating || 108));
  const position = escapeHtml(safeText(sticker.legendPosition || sticker.position, 'ICON'));
  const accent = escapeHtml(sticker.legendAccent || sticker.accent || '#f0b429');
  const accent2 = escapeHtml(sticker.legendAccent2 || sticker.accent2 || '#3a1c05');
  const img = escapeHtml(safeImageUrl(sticker.imageUrl || sticker.image_url || sticker.image) || '');
  const flag = sticker.countryCode ? countryFlag(sticker.countryCode) : '';
  const flagImgUrl = sticker.countryCode ? countryFlagImg(sticker.countryCode) : '';
  const flagHtmlIc = sticker.countryCode
    ? `<div class="ic-flag">${flagImgUrl ? `<img src="${escapeHtml(flagImgUrl)}" alt="${escapeHtml(sticker.countryCode.toUpperCase().slice(0,2))}" loading="lazy" onerror="this.outerHTML='<span>${escapeHtml(flag) || escapeHtml(sticker.countryCode.toUpperCase().slice(0,2))}</span>'">` : `<span>${escapeHtml(flag || sticker.countryCode.toUpperCase().slice(0,2))}</span>`}</div>`
    : '';
  const photo = img
    ? `<div class="ic-photo"><img src="${img}" alt="${name}" loading="lazy" onerror="const p=this.parentElement;if(!p)return;p.classList.add('fallback');this.remove()"></div>`
    : '<div class="ic-photo fallback"></div>';
  return `
    <div class="iconic-card${locked ? ' locked' : ''}" style="--ic-accent:${accent};--ic-accent2:${accent2}">
      <div class="ic-halo" aria-hidden="true"></div>
      <div class="ic-shine" aria-hidden="true"></div>
      <div class="ic-particles" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>
      <div class="ic-wreath ic-wreath-l" aria-hidden="true"></div>
      <div class="ic-wreath ic-wreath-r" aria-hidden="true"></div>
      <div class="ic-rating">
        <strong>${rating}</strong>
        <span>${position}</span>
        <em>ICON</em>
      </div>
      ${photo}
      ${flagHtmlIc}
      <div class="ic-plate">
        <div class="ic-name">${name}</div>
        <div class="ic-sub">✦ ${escapeHtml(safeText(sticker.legacyLabel, 'Bellator Icon'))}</div>
      </div>
      ${locked ? `<div class="ic-lock">🔒<span>~${ICONIC_DROP_PERCENT}% por sobre</span></div>` : ''}
    </div>`;
}

function renderIconicSpread(page) {
  const legend = page.playerSticker;
  const collected = Boolean(legend && legend.collected);
  const accent = escapeHtml(legend.legendAccent || '#f0b429');
  const accent2 = escapeHtml(legend.legendAccent2 || '#3a1c05');

  refs.pagePill.textContent = safeText(legend.legacyLabel, 'Leyenda').toUpperCase();
  refs.pageCaption.textContent = `${safeText(legend.legacyTag, 'ÍCONO')} · Edicion especial`;
  refs.pagePrev.style.visibility = '';
  refs.pageNext.style.visibility = '';
  refs.pagePrev.disabled = state.busy || state.currentPage === 0;
  refs.pageNext.disabled = state.busy || state.currentPage >= state.pages.length - 1;

  const isPending = state.pendingStickers.has(legend.id);
  const pasteOverlay = isPending ? `<div class="slot-paste-overlay" data-paste-id="${escapeHtml(legend.id)}"><div class="paste-icon">+</div><div class="paste-label">Pegar</div></div>` : '';
  const card = iconicCardMarkup(legend, { locked: !collected && !isPending });
  const powersHtml = Array.isArray(legend.legendPowers) && legend.legendPowers.length
    ? `<div class="legacy-power-list">${legend.legendPowers.map((power) => `<span>${escapeHtml(power)}</span>`).join('')}</div>`
    : '';
  const statusHtml = collected
    ? `<div class="legacy-status owned">✦ En tu colección${legend.quantity > 1 ? ` · x${legend.quantity} (una lista para intercambio)` : ''}</div>`
    : `<div class="legacy-status locked">Aún sin desbloquear · ~${ICONIC_DROP_PERCENT}% de aparición por sobre</div>`;

  refs.albumHost.innerHTML = `
    <div class="book-frame">
      <article class="iconic-spread${collected ? ' is-owned' : ' is-locked'}" style="--ic-accent:${accent};--ic-accent2:${accent2}">
        <div class="iconic-aura" aria-hidden="true"></div>
        <div class="iconic-rays" aria-hidden="true"></div>
        <section class="iconic-pane-card" data-sticker-id="${escapeHtml(legend.id)}">
          ${card}
          ${pasteOverlay}
        </section>
        <section class="iconic-pane-lore">
          <div class="legacy-tag">${escapeHtml(safeText(legend.legacyTag, 'ÍCONO'))}</div>
          <h2 class="legacy-title">${escapeHtml(safeText(legend.legacyLabel, 'Ícono Bellator'))}</h2>
          <div class="legacy-legend-name">${escapeHtml(legend.displayName)}</div>
          <div class="legacy-tagline">&ldquo;${escapeHtml(safeText(legend.legendTagline, ''))}&rdquo;</div>
          ${powersHtml}
          <div class="legacy-meta">
            <div class="legacy-chip"><span>Rareza</span><strong>✦ Icónico</strong></div>
            <div class="legacy-chip"><span>Aparición</span><strong>~${ICONIC_DROP_PERCENT}% por sobre</strong></div>
            <div class="legacy-chip"><span>Rating</span><strong>${escapeHtml(String(legend.legendRating || 108))}</strong></div>
          </div>
          ${statusHtml}
        </section>
      </article>
    </div>`;
    bindPasteOverlays();
}

function blackExtraCardMarkup(sticker, opts) {
  const options = opts || {};
  const locked = Boolean(options.locked);
  const name = escapeHtml(safeText(sticker.displayName || sticker.display_name || sticker.name, 'Extra'));
  const img = escapeHtml(safeImageUrl(sticker.imageUrl || sticker.image_url || sticker.image) || '');
  const note = escapeHtml(safeText(sticker.blackNote || sticker.black_note, 'Awarded for activity in Bellator'));
  const photo = img
    ? `<div class="bx-photo"><img src="${img}" alt="${name}" loading="lazy" onerror="const p=this.parentElement;if(!p)return;p.classList.add('fallback');this.remove()"></div>`
    : '<div class="bx-photo fallback"></div>';
  return `
    <div class="black-extra-card${locked ? ' locked' : ''}">
      <div class="bx-shine" aria-hidden="true"></div>
      <div class="bx-badge">EXTRA</div>
      ${photo}
      <div class="bx-plate">
        <div class="bx-name">${name}</div>
        <div class="bx-note">${note}</div>
      </div>
      ${locked ? '<div class="bx-lock">🔒<span>~2% per pack</span></div>' : `<div class="bx-owned">✦ In your collection${sticker.quantity > 1 ? ` · x${sticker.quantity}` : ''}</div>`}
    </div>`;
}

function renderDiamondSpread(page) {
  const sticker = page.specialSticker || page.playerSticker || (page.items || [])[0] || null;
  const collected = Boolean(sticker && sticker.collected);
  const accent = escapeHtml(sticker && sticker.legendAccent ? sticker.legendAccent : '#5dd7ff');
  const accent2 = escapeHtml(sticker && sticker.legendAccent2 ? sticker.legendAccent2 : '#0a1b32');
  const name = escapeHtml(safeText(sticker && sticker.displayName, 'Diamante'));
  const isPending = sticker && state.pendingStickers.has(sticker.id);
  const pasteOverlay = isPending ? `<div class="slot-paste-overlay" data-paste-id="${escapeHtml(sticker.id)}"><div class="paste-icon">+</div><div class="paste-label">Pegar</div></div>` : '';
  const card = legendaryDiamondCardMarkup(sticker || { name, rating: 109, position: 'ULTRA', image: '' });
  const powersHtml = Array.isArray(sticker && sticker.legendPowers) && sticker.legendPowers.length
    ? `<div class="legacy-power-list">${sticker.legendPowers.map((power) => `<span>${escapeHtml(power)}</span>`).join('')}</div>`
    : '';
  const statusHtml = collected
    ? `<div class="legacy-status owned">◈ En tu colección${sticker.quantity > 1 ? ` · x${sticker.quantity}` : ''}</div>`
    : `<div class="legacy-status locked">Aún sin desbloquear · carta ultra rara de diamante</div>`;

  refs.pagePill.textContent = '◈ DIAMANTE';
  refs.pageCaption.textContent = 'Edición ultra rara · Bellator';
  refs.pagePrev.style.visibility = '';
  refs.pageNext.style.visibility = '';
  refs.pagePrev.disabled = state.busy || state.currentPage === 0;
  refs.pageNext.disabled = state.busy || state.currentPage >= state.pages.length - 1;

  refs.albumHost.innerHTML = `
    <div class="book-frame">
      <article class="iconic-spread${collected ? ' is-owned' : ' is-locked'} diamond-spread" style="--ic-accent:${accent};--ic-accent2:${accent2}">
        <div class="iconic-aura" aria-hidden="true"></div>
        <div class="iconic-rays" aria-hidden="true"></div>
        <section class="iconic-pane-card" ${sticker ? `data-sticker-id="${escapeHtml(sticker.id)}"` : ''}>
          ${card}
          ${pasteOverlay}
        </section>
        <section class="iconic-pane-lore">
          <div class="legacy-tag">DIAMANTE</div>
          <h2 class="legacy-title">${name}</h2>
          <div class="legacy-legend-name">Carta ultrarrara Bellator</div>
          <div class="legacy-tagline">&ldquo;${escapeHtml(safeText(sticker && sticker.legendTagline, 'La pieza más brillante del álbum.'))}&rdquo;</div>
          ${powersHtml}
          <div class="legacy-meta">
            <div class="legacy-chip"><span>Rareza</span><strong>◈ Diamante</strong></div>
            <div class="legacy-chip"><span>Estado</span><strong>Ultra rara</strong></div>
            <div class="legacy-chip"><span>Rango</span><strong>${escapeHtml(String(sticker && sticker.legendRating ? sticker.legendRating : 109))}</strong></div>
          </div>
          ${statusHtml}
        </section>
      </article>
    </div>`;
    bindPasteOverlays();
}

function renderBlackExtrasSpread(page) {
  const extras = (page.items || []).slice(0, 3);
  const ownedCount = extras.filter((extra) => extra.collected).length;

  refs.pagePill.textContent = 'EXTRA STICKERS · BLACK';
  refs.pageCaption.textContent = 'Bellator Rewards · Edicion especial';
  refs.pagePrev.style.visibility = '';
  refs.pageNext.style.visibility = '';
  refs.pagePrev.disabled = state.busy || state.currentPage === 0;
  refs.pageNext.disabled = state.busy || state.currentPage >= state.pages.length - 1;

  const cards = extras.map((extra) => {
    const isPending = state.pendingStickers.has(extra.id);
    const pasteOverlay = isPending ? `<div class="slot-paste-overlay" data-paste-id="${escapeHtml(extra.id)}"><div class="paste-icon">+</div><div class="paste-label">Pegar</div></div>` : '';
    const markup = blackExtraCardMarkup(extra, { locked: !extra.collected && !isPending });
    return `<div data-sticker-id="${escapeHtml(extra.id)}" style="position:relative">${markup}${pasteOverlay}</div>`;
  }).join('');

  refs.albumHost.innerHTML = `
    <div class="book-frame">
      <article class="black-extras-spread">
        <div class="bxs-glow" aria-hidden="true"></div>
        <header class="bxs-head">
          <div class="bxs-kicker">◆ Only 3 in all of Bellator</div>
          <h2 class="bxs-title">Black Border Cards</h2>
          <p class="bxs-sub">They don't drop in normal packs. They were earned through real consistency inside the arena. Three warriors who kept Bellator's fire alive from day one. If one reaches you, stop. Not everyone sees one in a whole season.</p>
          <div class="bxs-count">${ownedCount} / 3 owned · ≈2% per pack</div>
        </header>
        <div class="aos-power-list" style="margin:0 0 18px;max-width:780px">
          <span>Official black perk: +12 hours of response time in a trade.</span>
          <span>You can use it for yourself or hand it to your comrade within the same negotiation.</span>
        </div>
        <div class="bxs-grid">
          ${cards}
        </div>
      </article>
    </div>`;
    bindPasteOverlays();
}

function renderAlbumOverviewSpread(page) {
  refs.pagePill.textContent = 'VISTA DEL ÁLBUM';
  refs.pageCaption.textContent = 'Antes de empezar · Guia';
  refs.pagePrev.style.visibility = '';
  refs.pageNext.style.visibility = '';
  refs.pagePrev.disabled = state.busy || state.currentPage === 0;
  refs.pageNext.disabled = state.busy || state.currentPage >= state.pages.length - 1;

  refs.albumHost.innerHTML = `
    <div class="book-frame">
      <article class="album-overview-spread">
        <div class="aos-glow" aria-hidden="true"></div>
        <header class="aos-head">
          <div class="aos-kicker">Tres niveles que cambian la colección</div>
          <h2 class="aos-title">Cómo golpea el álbum de Bellator</h2>
          <p class="aos-sub">No todo aquí vale lo mismo. Las negras aceleran intercambios, los íconos alteran combates y las dos especiales extremas de cada jugador te dejan elegir el beneficio que más te convenga.</p>
        </header>
        <div class="aos-grid">
          <section class="aos-panel dark">
            <div class="aos-panel-top">
              <span class="aos-badge black">◆ Negras</span>
              <span class="aos-drop">≈2%</span>
            </div>
            <div class="aos-power-list">
              <span>Solo 3 en toda la colección base.</span>
              <span>Dan +12 horas de respuesta en un intercambio.</span>
              <span>Puedes usarla para ti o para tu camarada.</span>
            </div>
            <div class="aos-note">Son las láminas que convierten una negociación normal en una con margen, presión y ventaja táctica.</div>
          </section>
          <section class="aos-panel gold">
            <div class="aos-panel-top">
              <span class="aos-badge gold">✦ Icónicos</span>
              <span class="aos-drop">≈3%</span>
            </div>
            <div class="aos-power-list">
              <span><strong>Bandet</strong>: +15% energía, -15% energía rival, 1 hax prohibido.</span>
              <span><strong>Ember</strong>: +10 vida y 2 turnos límite seguidos sin gastar la energía de 1.</span>
              <span><strong>Akira / Merus / Inverse / Ego / Red</strong>: null power, ruptura de defensa, buffs de vida, tiempo y potencia.</span>
            </div>
            <div class="aos-note">No son solo doradas: son cartas con habilidades, peso de lore y una página propia dentro del libro.</div>
          </section>
          <section class="aos-panel mythic">
            <div class="aos-panel-top">
              <span class="aos-badge gold">◈ Especiales extremas</span>
              <span class="aos-drop">1% / 0.5%</span>
            </div>
            <div class="aos-tier-grid">
              <div class="aos-tier"><strong>Dorada</strong><em>Muy rara · 1%</em></div>
              <div class="aos-tier"><strong>Negro · oro · diamante</strong><em>Casi mítica · 0.5%</em></div>
            </div>
            <div class="aos-note">Cada jugador tiene estas dos versiones finales. Si te toca una, eliges 1 beneficio de cualquier lámina negra o icónica y lo reclamas para esa situación.</div>
          </section>
        </div>
        <div class="aos-hint">Orden del álbum: Universal → guía Bellator → Ciudad → Coming Soon</div>
      </article>
    </div>`;
}

function renderComingSoonSpread(page) {
  refs.pagePill.textContent = 'COMING SOON';
  refs.pageCaption.textContent = 'Próximamente · Última página';
  refs.pagePrev.style.visibility = '';
  refs.pageNext.style.visibility = '';
  refs.pagePrev.disabled = state.busy || state.currentPage === 0;
  refs.pageNext.disabled = state.busy || state.currentPage >= state.pages.length - 1;

  refs.albumHost.innerHTML = `
    <div class="book-frame">
      <article class="album-overview-spread">
        <div class="aos-glow" aria-hidden="true"></div>
        <header class="aos-head">
          <div class="aos-kicker">El libro sigue creciendo</div>
          <h2 class="aos-title">Coming Soon</h2>
          <p class="aos-sub">Aquí caerán las próximas expansiones del álbum Bellator. Nuevos peleadores, nuevas divisiones y nuevas recompensas quedarán ancladas después del roster actual sin romper tu colección.</p>
        </header>
        <div class="aos-grid">
          <section class="aos-panel dark">
            <div class="aos-panel-top">
              <span class="aos-badge gold">Siguiente ola</span>
              <span class="aos-drop">En preparación</span>
            </div>
            <div class="aos-power-list">
              <span>Más perfiles exclusivos sin contaminar el roster actual.</span>
              <span>Páginas nuevas añadidas al final del libro.</span>
              <span>El progreso ya pegado seguirá intacto.</span>
            </div>
            <div class="aos-note">Esta hoja existe para reservar el cierre del álbum sin mezclarla con los peleadores activos.</div>
          </section>
        </div>
        <div class="aos-hint">Fin del libro actual · espera la próxima expansión</div>
      </article>
    </div>`;
}

function renderIconInfoSpread(page) {
  refs.pagePill.textContent = 'GUÍA DE ÍCONOS';
  refs.pageCaption.textContent = 'Como funcionan · Guia';
  refs.pagePrev.style.visibility = '';
  refs.pageNext.style.visibility = '';
  refs.pagePrev.disabled = state.busy || state.currentPage === 0;
  refs.pageNext.disabled = state.busy || state.currentPage >= state.pages.length - 1;

  refs.albumHost.innerHTML = `
    <div class="book-frame">
      <article class="icon-info-spread">
        <div class="iis-aura" aria-hidden="true"></div>
        <div class="iis-rays" aria-hidden="true"></div>
        <div class="iis-sparks" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>
        <div class="iis-content">
          <div class="iis-crown">✦</div>
          <div class="iis-kicker">Más allá del libro ordinario</div>
          <h2 class="iis-title">Los Inmortales de Bellator</h2>
          <p class="iis-lead">A partir de aquí el álbum deja de ser puro coleccionismo y se vuelve ventaja. Cada ícono tiene un efecto directo. Bandet es el ejemplo perfecto: cuando cae, no solo luce épico, cambia una pelea.</p>
          <div class="iis-bandet-show">
            <div class="iis-bandet-label">Ejemplo icónico</div>
            <div class="iis-bandet-title">BANDET · Orochi Legacy</div>
            <div class="iis-bandet-copy">Su lámina representa poder ofensivo total: si la consigues, llevas presencia, control y un hax prohibido a la mesa.</div>
            <div class="iis-bandet-list">
              <span>+15% de energía propia</span>
              <span>-15% de energía rival</span>
              <span>1 hax prohibido desbloqueado</span>
            </div>
          </div>
          <div class="iis-steps">
            <div class="iis-step">
              <div class="iis-step-ico">✦</div>
              <div class="iis-step-title">1 de cada 33 sobres</div>
              <div class="iis-step-text">Abrir uno es un evento. La mayoría de coleccionistas pasan temporadas enteras sin verlos.</div>
            </div>
            <div class="iis-step">
              <div class="iis-step-ico">♛</div>
              <div class="iis-step-title">Habilidad real</div>
              <div class="iis-step-text">No son puro lore: cada ícono trae un beneficio concreto, desde energía y vida hasta null power, hax, tiempo o daño.</div>
            </div>
            <div class="iis-step">
              <div class="iis-step-ico">◆</div>
              <div class="iis-step-title">Página legendaria</div>
              <div class="iis-step-text">Dorada, animada y exclusiva. No comparte espacio con nadie. Cuando la abres, el libro cambia de tono.</div>
            </div>
          </div>
          <div class="iis-hint">Desliza para enfrentarlos →</div>
        </div>
      </article>
    </div>`;
}

function renderAlbum() {
  syncMobilePageTaps();
  if (state.loading) {
    renderBookState('Cargando libro', 'Sincronizando roster, cromos y estado de la coleccion.', 'loading');
    return;
  }

  if (!state.pages.length) {
    renderBookState('Sin catalogo', 'No se pudo cargar ninguna serie del album. Revisa la API o vuelve a intentar en unos segundos.', 'empty');
    return;
  }

  const page = state.pages[Math.max(0, Math.min(state.currentPage, state.pages.length - 1))];
  if (page.isAlbumOverview) {
    renderAlbumOverviewSpread(page);
    if (recordVisitedPage(state.currentPage)) updateHeaderSummary();
    return;
  }
  if (page.isIconInfo) {
    renderIconInfoSpread(page);
    if (recordVisitedPage(state.currentPage)) updateHeaderSummary();
    return;
  }
  if (page.isBlackExtras) {
    renderBlackExtrasSpread(page);
    if (recordVisitedPage(state.currentPage)) updateHeaderSummary();
    return;
  }
  if (page.isDiamond) {
    renderDiamondSpread(page);
    if (recordVisitedPage(state.currentPage)) updateHeaderSummary();
    return;
  }
  if (page.isComingSoon) {
    renderComingSoonSpread(page);
    if (recordVisitedPage(state.currentPage)) updateHeaderSummary();
    return;
  }
  if (page.isIconic) {
    renderIconicSpread(page);
    if (recordVisitedPage(state.currentPage)) updateHeaderSummary();
    return;
  }
  const playerSticker = page.playerSticker;
  const colors = spreadColors(playerSticker);
  const collected = page.collectedCount;
  const total = page.totalCount;
  const progress = Math.round((collected / Math.max(total, 1)) * 100);
  const record = `${playerSticker ? playerSticker.wins : 0}-${playerSticker ? playerSticker.losses : 0}-${playerSticker ? playerSticker.draws : 0}`;
  const streak = playerSticker ? playerSticker.currentStreak : 0;
  const rank = playerSticker ? playerSticker.rankingPoints : 0;
  const clan = playerSticker ? safeText(playerSticker.clanName, 'Sin clan') : 'Sin clan';
  const division = escapeHtml(page.groupLabel || 'Universal');
  const rosterTotal = rosterPageCount();
  const rosterIndex = rosterPageIndex(page);

  refs.pagePill.textContent = (page.rawName || 'Album').toUpperCase();
  refs.pageCaption.textContent = rosterTotal
    ? `Division ${division} · ${rosterIndex} / ${rosterTotal}`
    : `Division ${division}`;
  refs.pagePrev.style.visibility = '';
  refs.pageNext.style.visibility = '';
  refs.pagePrev.disabled = state.busy || state.currentPage === 0;
  refs.pageNext.disabled = state.busy || state.currentPage >= state.pages.length - 1;

  const heroPhoto = playerSticker && playerSticker.imageUrl
    ? `<div class="hero-photo"><img src="${escapeHtml(playerSticker.imageUrl)}" alt="${escapeHtml(page.rawName)}" onerror="const root=this.parentElement;if(!root)return;root.classList.add('fallback');this.remove()"></div>`
    : '<div class="hero-photo fallback"></div>';

  const slotProfile = renderAlbumSlot(page.collectibleStickers[0] || null, 'Perfil');
  const slotOne = renderAlbumSlot(page.collectibleStickers[1] || null, 'PJ 1');
  const slotTwo = renderAlbumSlot(page.collectibleStickers[2] || null, 'PJ 2');
  const slotThree = renderAlbumSlot(page.collectibleStickers[3] || null, 'PJ 3');

  refs.albumHost.innerHTML = `
    <div class="book-frame">
      <article class="album-spread" style="--sp-color-a:${escapeHtml(colors.main)};--sp-color-b:${escapeHtml(colors.accent2)};--accent:${escapeHtml(colors.accent)};--page-bg:#0c1832;">
        <div class="spread-content">
          <section class="spread-pane left">
            ${heroPhoto}
            <div class="hero-white-arc" aria-hidden="true"></div>
            <div class="hero-radials" aria-hidden="true"></div>
            <div class="hero-gradient" aria-hidden="true"></div>
            <div class="hero-watermark" aria-hidden="true">26</div>
            <div class="hero-content">
              <div class="hero-topline">
                <div class="hero-chip">${escapeHtml(playerSticker ? formatSlotLabel(playerSticker.slotNumber) : '#000')}</div>
                <div class="hero-division">${division}</div>
                ${playerSticker && playerSticker.countryCode ? `<div class="hero-flag"><img src="${countryFlagImg(playerSticker.countryCode)}" alt="${escapeHtml(playerSticker.countryCode.toUpperCase().slice(0,2))}" loading="lazy" onerror="this.outerHTML='<span>${escapeHtml(countryFlag(playerSticker.countryCode))}</span>'"></div>` : ''}
              </div>
              <div class="hero-copy">
                <div class="we-are">We Are</div>
                <span class="player-name">${escapeHtml(page.rawName || 'Competidor')}</span>
                <p>${escapeHtml(clan)} · Rareza ${escapeHtml(rarityLabel(playerSticker ? playerSticker.rarity : 'comun'))}</p>
              </div>
              <div class="hero-footer">
                <div class="hero-stat"><span>W</span><strong>${escapeHtml(String(playerSticker ? playerSticker.wins : 0))}</strong></div>
                <div class="hero-stat"><span>L</span><strong>${escapeHtml(String(playerSticker ? playerSticker.losses : 0))}</strong></div>
                <div class="hero-stat"><span>Racha</span><strong>${escapeHtml(String(streak))}</strong></div>
                <div class="hero-stat"><span>★</span><strong>${escapeHtml(String(rank))}</strong></div>
              </div>
            </div>
          </section>
          <section class="spread-pane right">
            <div class="spread-page-label">Bellator · ${division} · Pág ${page.pageNumber}</div>
            <div class="spread-grid">
              ${slotProfile}
              ${slotOne}
              ${slotTwo}
              ${slotThree}
              <aside class="spread-stats-card">
                <div class="stats-label">Perfil</div>
                <div class="stats-name">${escapeHtml(page.rawName || 'Competidor')}</div>
                <div class="stats-list">
                  <div class="stats-row"><span>División</span><strong>${escapeHtml(division)}</strong></div>
                  <div class="stats-row"><span>Clan</span><strong>${escapeHtml(clan)}</strong></div>
                  <div class="stats-row"><span>Victorias</span><strong>${escapeHtml(String(playerSticker ? playerSticker.wins : 0))}</strong></div>
                  <div class="stats-row"><span>Derrotas</span><strong>${escapeHtml(String(playerSticker ? playerSticker.losses : 0))}</strong></div>
                  <div class="stats-row"><span>Racha</span><strong>${escapeHtml(String(streak))}</strong></div>
                  <div class="stats-row"><span>Ranking ★</span><strong>${escapeHtml(String(rank))}</strong></div>
                  ${playerSticker && playerSticker.countryCode ? `<div class="stats-row"><span>País</span><strong>${escapeHtml(countryFlag(playerSticker.countryCode))}</strong></div>` : ''}
                </div>
              </aside>
            </div>
            <div class="spread-collected-bar">
              <span>${collected} / ${total} cromos pegados</span>
              <strong>${progress}%</strong>
            </div>
          </section>
        </div>
      </article>
    </div>`;

  refs.albumHost.querySelectorAll('[data-sticker-id]').forEach((button) => {
    button.addEventListener('click', () => {
      if (button.dataset.pending) return; // paste overlay handles its own click
      openOverlay(button.getAttribute('data-sticker-id'));
    });
  });

  bindPasteOverlays();

  if (recordVisitedPage(state.currentPage)) {
    updateHeaderSummary();
  }
}

function renderOverlay() {
  const sticker = state.overlayPool[state.overlayIndex];
  if (!sticker) return;
  refs.overlayCardHost.innerHTML = stickerCardMarkup(sticker);
  refs.overlayPrev.disabled = state.overlayIndex === 0;
  refs.overlayNext.disabled = state.overlayIndex === state.overlayPool.length - 1;
}

function openOverlay(stickerId) {
  const page = state.pages[state.currentPage];
  if (!page) return;
  state.overlayPool = page.items.filter((item) => item.collected);
  state.overlayIndex = Math.max(0, state.overlayPool.findIndex((item) => item.id === stickerId));
  if (!state.overlayPool.length) return;
  renderOverlay();
  refs.overlay.classList.add('show');
  refs.overlay.setAttribute('aria-hidden', 'false');
}

function closeOverlay() {
  refs.overlay.classList.remove('show');
  refs.overlay.setAttribute('aria-hidden', 'true');
}

async function fetchJson(url, options) {
  const sameOrigin = typeof url === 'string' && (url.startsWith('/') || url.startsWith(window.location.origin));
  const baseHeaders = options && options.headers ? { ...options.headers } : {};
  if (!sameOrigin && shouldUseRemoteAlbumApi() && state.sessionToken) {
    baseHeaders.Authorization = `Bearer ${state.sessionToken}`;
  }
  const response = await fetch(url, {
    credentials: sameOrigin ? 'same-origin' : 'include',
    ...(options || {}),
    headers: baseHeaders,
  });
  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await response.json() : null;
  if (!response.ok) {
    const message = data && data.error ? data.error : `Error ${response.status}`;
    throw new Error(message);
  }
  return data;
}

function requestHeaders(includeJson) {
  const headers = {};
  if (includeJson) headers['Content-Type'] = 'application/json';
  if (!hasActiveSession() && state.legacyPlayerKey) headers['X-Player-Key'] = state.legacyPlayerKey;
  if (state.sessionToken && shouldUseRemoteAlbumApi()) headers.Authorization = `Bearer ${state.sessionToken}`;
  return headers;
}

function applyCatalogState(stickers, mode, baseStickers) {
  state.catalogMode = mode;
  const isSpecial = (s) => s.isIconic || s.isBlackExtra || 
    safeText(s.specialType, '').toLowerCase() === 'iconico' || 
    safeText(s.specialType, '').toLowerCase() === 'extra' || 
    safeText(s.specialType, '').toLowerCase() === 'diamante' ||
    safeText(s.specialType, '').toLowerCase() === 'esmeralda';
    
  const cleanBase = (baseStickers || stickers).filter((sticker) => !isSpecial(sticker));
  const cleanDisplay = stickers.filter((sticker) => !isSpecial(sticker));
  const iconics = iconicStickersWithCollection(stickers);
  const blackExtras = blackExtrasWithCollection(stickers);
  const diamonds = stickers.filter((sticker) => safeText(sticker.specialType, '').toLowerCase() === 'diamante');
  
  const esmeraldas = stickers.filter((sticker) => safeText(sticker.specialType, '').toLowerCase() === 'esmeralda');
  
  // Asignar imagen del roster normal al diamante y esmeralda si no tienen
  diamonds.concat(esmeraldas).forEach(dia => {
    const basePseudo = (dia.playerPseudo || '').replace('_DIAMOND', '').replace('_EMERALD', '').replace('_ESMERALDA', '');
    const normalSticker = cleanDisplay.find(s => 
      s.stickerType === 'player' && s.variant === 'normal' && s.playerPseudo === basePseudo
    );
    if (normalSticker && !dia.imageUrl) {
      dia.imageUrl = normalSticker.imageUrl;
    }
  });

  state.baseStickers = cleanBase.map((sticker) => ({ ...sticker }));
  state.stickers = cleanDisplay.map((sticker) => ({ ...sticker }))
    .concat(blackExtras.map((sticker) => ({ ...sticker })))
    .concat(iconics.map((sticker) => ({ ...sticker })))
    .concat(diamonds.map((sticker) => ({ ...sticker })))
    .concat(esmeraldas.map((sticker) => ({ ...sticker })));
  const bookStickers = cleanDisplay.map((sticker) => ({ ...sticker }))
    .concat(blackExtras.map((sticker) => ({ ...sticker })))
    .concat(iconics.map((sticker) => ({ ...sticker })));
  
  state.pages = groupedPages(bookStickers);
  if (state.currentPage >= state.pages.length) {
    state.currentPage = Math.max(0, state.pages.length - 1);
  }
  updateHeaderSummary();
  if (state.currentScene === 'album') renderAlbum();
  if (state.currentScene === 'reveal') {
    if (state.revealPhase === 'pack') renderPackOpening();
    if (state.revealPhase === 'cards') renderReveal();
    syncRevealPhase();
  }
}

async function loadPreviewRosterMode(statusMessage) {
  const roster = await fetchJson(rosterApiUrl());
  const baseStickers = buildPreviewCatalogFromRoster(roster);
  state.previewCollection = loadPreviewCollection();
  state.loading = false;
  applyCatalogState(applyPreviewCollection(baseStickers, state.previewCollection), 'preview', baseStickers);
  if (statusMessage) setStatus(statusMessage, '');
}

function pickPreviewPack() {
  const pool = state.baseStickers.filter((s) => safeText(s.displayName, '') !== '' && !s.isIconic && !s.isBlackExtra);
  const coll = loadPreviewCollection();
  // Split into collected (repeats) and fresh pools for high-repeat mechanic
  const collectedPool = pool.filter((s) => (coll[s.id] || 0) > 0);
  const freshPool = pool.filter((s) => (coll[s.id] || 0) === 0);
  const picks = [];
  const target = Math.min(PREVIEW_PACK_SIZE, pool.length);

  while (picks.length < target) {
    // 68% chance of repeat once you have collected stickers
    const preferRepeat = collectedPool.length > 0 && (freshPool.length === 0 || randomIndex(100) < 68);
    const basePool = preferRepeat ? collectedPool : (freshPool.length ? freshPool : pool);
    const desiredRarity = weightedPreviewRarity();
    const byRarity = basePool.filter((s) => s.rarity === desiredRarity && !picks.find((p) => p.id === s.id));
    const candidates = (byRarity.length ? byRarity : basePool).filter((s) => !picks.find((p) => p.id === s.id));
    if (!candidates.length) break;
    picks.push(candidates[randomIndex(candidates.length)]);
  }
  return picks;
}

function openPreviewPack() {
  const pack = pickPreviewPack();
  if (!pack.length) {
    setStatus('No hay cromos disponibles para el preview.', 'error');
    return;
  }

  const collection = loadPreviewCollection();
  let newCount = 0;
  state.currentPack = pack.map((sticker) => {
    const nextQuantity = Number(collection[sticker.id] || 0) + 1;
    if (nextQuantity === 1) newCount += 1;
    collection[sticker.id] = nextQuantity;
    return {
      ...sticker,
      quantity: nextQuantity,
      collected: true,
      isNew: nextQuantity === 1,
    };
  });

  // 1% Black Border upgrade per sticker — ultra rare variant
  state.currentPack = state.currentPack.map((sticker) => {
    if (randomIndex(100) === 0) {
      return { ...sticker, variant: 'blackborder', rarity: 'blackborder', isNew: true };
    }
    return sticker;
  });

  // ◆ Cromo EXTRA de borde negro — aparición ≈3% por sobre: reemplaza una lámina
  let blackHit = null;
  if (randomIndex(100) < BLACK_EXTRA_DROP_PERCENT) {
    const drop = pickBlackExtraDrop();
    if (drop) {
      const nextQuantity = Number(collection[drop.id] || 0) + 1;
      collection[drop.id] = nextQuantity;
      const replaceIndex = randomIndex(state.currentPack.length);
      state.currentPack[replaceIndex] = {
        ...drop,
        quantity: nextQuantity,
        collected: true,
        isNew: nextQuantity === 1,
      };
      blackHit = drop;
    }
  }

  // ✦ Icónico de leyenda — aparición ≈3% por sobre: reemplaza una lámina
  let iconicHit = null;
  if (randomIndex(100) < ICONIC_DROP_PERCENT) {
    const drop = pickIconicDrop();
    if (drop) {
      const nextQuantity = Number(collection[drop.id] || 0) + 1;
      collection[drop.id] = nextQuantity;
      const replaceIndex = randomIndex(state.currentPack.length);
      state.currentPack[replaceIndex] = {
        ...drop,
        quantity: nextQuantity,
        collected: true,
        isNew: nextQuantity === 1,
      };
      iconicHit = drop;
    }
  }

  function pickSpecialDrop(specialType) {
    if (!Array.isArray(state.stickers)) return null;
    const pool = state.stickers.filter(s => safeText(s.specialType, '').toLowerCase() === specialType);
    if (!pool.length) return null;
    const coll = loadPreviewCollection();
    const unowned = pool.filter(s => !(Number(coll[s.id] || 0) > 0));
    const finalPool = unowned.length ? unowned : pool;
    return finalPool[randomIndex(finalPool.length)] || null;
  }

  // 💎 Diamante — aparición ≈2% por sobre
  let diamanteHit = null;
  if (randomIndex(100) < 2) {
    const drop = pickSpecialDrop('diamante');
    if (drop) {
      const nextQuantity = Number(collection[drop.id] || 0) + 1;
      collection[drop.id] = nextQuantity;
      const replaceIndex = randomIndex(state.currentPack.length);
      state.currentPack[replaceIndex] = {
        ...drop,
        quantity: nextQuantity,
        collected: true,
        isNew: nextQuantity === 1,
      };
      diamanteHit = drop;
    }
  }

  // 🟢 Esmeralda — aparición ≈1% por sobre
  let esmeraldaHit = null;
  if (randomIndex(100) < 1) {
    const drop = pickSpecialDrop('esmeralda');
    if (drop) {
      const nextQuantity = Number(collection[drop.id] || 0) + 1;
      collection[drop.id] = nextQuantity;
      const replaceIndex = randomIndex(state.currentPack.length);
      state.currentPack[replaceIndex] = {
        ...drop,
        quantity: nextQuantity,
        collected: true,
        isNew: nextQuantity === 1,
      };
      esmeraldaHit = drop;
    }
  }

  savePreviewCollection(collection);
  applyCatalogState(applyPreviewCollection(state.baseStickers, collection), 'preview', state.baseStickers);

  const claim = claimDailyPackQuota();
  startPackCountdown();
  recordNewStickers(newCount);
  state.currentPack = state.currentPack.map((sticker) => ({
    ...sticker,
    quantity: Number(collection[sticker.id] || 0),
    collected: true,
    isNew: true,
  }));

  // Populate pending stickers for paste mechanic
  state.currentPack.forEach((s) => {
    if (s.isNew) state.pendingStickers.add(s.id);
  });
  savePendingStickers();
  updatePendingTray();

  startPackRevealFlow();
  const blackNote = blackHit ? ` · ◆ ¡EXTRA NEGRO ${blackHit.name}!` : '';
  const iconicNote = iconicHit ? ` · ✦ ¡ICÓNICO ${iconicHit.name}!` : '';
  setStatus(`Sobre gratis reclamado: ${claim.count}/${DAILY_FREE_PACK_LIMIT} en 24 horas · ${newCount} cromo(s) nuevos.${blackNote}${iconicNote}`, 'success');
}

async function loadAlbumData(options = {}) {
  const { silent = false } = options;
  state.loading = true;
  updateHeaderSummary();
  if (state.currentScene === 'album') renderAlbum();
  if (!silent) setStatus('Cargando album...', '');

  if (!shouldUseRemoteAlbumApi() && shouldUseStandaloneAlbumMode()) {
    try {
      await loadPreviewRosterMode(
        silent
          ? ''
          : hasAlbumIdentity()
            ? `Album Bellator cargado en modo local para ${currentPlayerLabel()}.`
            : 'Album Bellator cargado en modo vista previa.'
      );
    } catch (fallbackError) {
      state.loading = false;
      state.catalogMode = 'unknown';
      state.baseStickers = [];
      state.stickers = [];
      state.pages = [];
      updateHeaderSummary();
      if (state.currentScene === 'album') renderAlbum();
      setStatus(`No se pudo cargar el album: ${fallbackError.message}.`, 'error');
    }
    return;
  }

  try {
    await loadRemoteMissionConfig();
    await loadAlbumViewerSummary();
    let stickers;
    if (hasAlbumIdentity()) {
      stickers = await fetchJson(albumApiUrl('/api/album/collection'), { headers: requestHeaders(false) });
      if (!silent) {
        setStatus(hasActiveSession() ? `Album sincronizado con ${currentPlayerLabel()}.` : 'Album sincronizado con acceso legado.', 'success');
      }
    } else {
      stickers = await fetchJson(albumApiUrl('/api/album/catalog'));
      if (!silent) setStatus('Libro Bellator cargado.', 'success');
    }

    state.loading = false;
    applyCatalogState(Array.isArray(stickers) ? stickers.map(normalizeSticker) : [], 'server');
    state.previewCollection = loadPreviewCollection();
  } catch (error) {
    try {
      await loadPreviewRosterMode(
        silent
          ? ''
          : hasActiveSession()
            ? `Sincronizacion remota del album no disponible para ${currentPlayerLabel()} (${error.message}). Usando roster activo Bellator mientras termina el despliegue.`
            : hasLegacyAccess()
              ? `Sincronizacion heredada del album no disponible (${error.message}). Usando roster activo Bellator mientras termina el despliegue.`
              : 'Sincronizacion publica del album no disponible. Usando roster activo Bellator mientras termina el despliegue.'
      );
    } catch (fallbackError) {
      state.loading = false;
      state.catalogMode = 'unknown';
      state.baseStickers = [];
      state.stickers = [];
      state.pages = [];
      updateHeaderSummary();
      if (state.currentScene === 'album') renderAlbum();
      setStatus(`No se pudo cargar el album: ${fallbackError.message}.`, 'error');
    }
  }
}

async function syncKey() {
  const pseudonimo = safeText(refs.pseudoInput.value, '');
  const playerKey = safeText(refs.keyInput.value, '');
  if (!pseudonimo || !playerKey) {
    setStatus('Escribe tu pseudonimo y tu clave Bellator para activar la coleccion real.', 'error');
    return;
  }

  state.busy = true;
  refs.saveKeyButton.disabled = true;
  refs.clearKeyButton.disabled = true;
  updateHeaderSummary();
  setStatus('Validando acceso Bellator...', '');

  try {
    if (!shouldUseRemoteAlbumApi() && shouldUseStandaloneAlbumMode()) {
      activateLocalSession(pseudonimo, '');
      refs.pseudoInput.value = pseudonimo;
      refs.keyInput.value = '';
      await loadAlbumData({ silent: true });
      setStatus(`Sesion iniciada como ${pseudonimo} (modo album local).`, 'success');
      alert(`✅ ¡Sesión iniciada!\n\nEntraste como "${pseudonimo}".\nYa puedes abrir sobres y llenar tu álbum.`);
      if (refs.identityPanelWrap) refs.identityPanelWrap.hidden = true;
      if (refs.accederToggle) refs.accederToggle.textContent = '🔑 Acceder / Registrarse ▾';
      return;
    }

    const data = await fetchJson(albumApiUrl('/api/album/session'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pseudonimo, player_key: playerKey }),
    });
    persistAlbumSessionToken(data && data.token);
    resetTradeState();
    state.session = normalizeAlbumSession(data && data.session);
    state.playerPseudo = safeText(state.session && state.session.pseudonimo, pseudonimo);
    state.legacyPlayerKey = '';
    localStorage.setItem(PSEUDONIMO_STORAGE_KEY, state.playerPseudo);
    localStorage.removeItem(LEGACY_PLAYER_KEY_STORAGE_KEY);
    refs.pseudoInput.value = state.playerPseudo;
    refs.keyInput.value = '';
    await loadAlbumData({ silent: true });
    setStatus(`Sesion Bellator activa para ${state.playerPseudo}.`, 'success');
    alert(`✅ ¡Sesión iniciada!\n\nEntraste como "${state.playerPseudo}".\nYa puedes abrir sobres y llenar tu álbum.`);
  } catch (error) {
    if (usesStaticRouteMap()) {
      activateLocalSession(pseudonimo, '');
      refs.pseudoInput.value = pseudonimo;
      refs.keyInput.value = '';
      await loadAlbumData({ silent: true });
      setStatus(`Sesión iniciada como ${pseudonimo} (modo local).`, 'success');
      alert(`✅ ¡Sesión iniciada!\n\nEntraste como "${pseudonimo}".\nYa puedes abrir sobres y llenar tu álbum.`);
      if (refs.identityPanelWrap) refs.identityPanelWrap.hidden = true;
      if (refs.accederToggle) refs.accederToggle.textContent = '🔑 Acceder / Registrarse ▾';
    } else {
      state.session = null;
      state.albumViewer = null;
      updateHeaderSummary();
      setStatus(`No se pudo iniciar sesión Bellator: ${error.message}.`, 'error');
    }
  } finally {
    state.busy = false;
    refs.saveKeyButton.disabled = false;
    refs.clearKeyButton.disabled = false;
    updateHeaderSummary();
  }
}

async function registerQuickIdentity() {
  const pseudonimo = safeText(refs.registerPseudoInput.value, '');
  const playerKey = safeText(refs.registerKeyInput ? refs.registerKeyInput.value : refs.keyInput.value, '');
  const countryCode = safeText(refs.registerCountrySelect.value, '');
  if (!pseudonimo) {
    setStatus('Escribe el pseudónimo que quieres registrar.', 'error');
    refs.registerPseudoInput.focus();
    return;
  }
  if (!playerKey) {
    setStatus('Crea una clave Bellator para tu cuenta.', 'error');
    (refs.registerKeyInput || refs.keyInput).focus();
    return;
  }
  if (!countryCode) {
    setStatus('Selecciona tu país antes de registrarte.', 'error');
    refs.registerCountrySelect.focus();
    return;
  }

  state.busy = true;
  refs.saveKeyButton.disabled = true;
  refs.registerFastButton.disabled = true;
  refs.clearKeyButton.disabled = true;
  updateHeaderSummary();
  setStatus('Creando identidad Bellator...', '');

  try {
    if (!shouldUseRemoteAlbumApi() && shouldUseStandaloneAlbumMode()) {
      activateLocalSession(pseudonimo, countryCode);
      refs.pseudoInput.value = pseudonimo;
      refs.registerPseudoInput.value = pseudonimo;
      if (refs.registerKeyInput) refs.registerKeyInput.value = '';
      refs.keyInput.value = '';
      await loadAlbumData({ silent: true });
      setStatus(`Cuenta creada para ${pseudonimo} (modo album local).`, 'success');
      alert(`✅ ¡Cuenta creada!\n\nTu cuenta "${pseudonimo}" quedó registrada.\nYa puedes abrir sobres y llenar tu álbum.`);
      refs.identityPanelWrap.hidden = true;
      refs.accederToggle.textContent = '🔑 Acceder / Registrarse ▾';
      return;
    }

    const fingerprint = await generateAlbumFingerprint();
    const data = await fetchJson(albumApiUrl('/api/album/register'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pseudonimo,
        player_key: playerKey,
        country_code: countryCode,
        hardware_fingerprint: fingerprint,
      }),
    });
    persistAlbumSessionToken(data && data.token);
    resetTradeState();
    state.session = normalizeAlbumSession(data && data.session);
    state.playerPseudo = safeText(state.session && state.session.pseudonimo, pseudonimo);
    state.legacyPlayerKey = '';
    localStorage.setItem(PSEUDONIMO_STORAGE_KEY, state.playerPseudo);
    localStorage.removeItem(LEGACY_PLAYER_KEY_STORAGE_KEY);
    refs.pseudoInput.value = state.playerPseudo;
    refs.registerPseudoInput.value = state.playerPseudo;
    refs.keyInput.value = '';
    await loadAlbumData({ silent: true });
    setStatus(`Cuenta Bellator creada para ${state.playerPseudo}. Ya puedes entrar al álbum.`, 'success');
    alert(`✅ ¡Cuenta creada!\n\nTu cuenta "${state.playerPseudo}" quedó registrada.\nYa puedes abrir sobres y llenar tu álbum.`);
    refs.identityPanelWrap.hidden = true;
    refs.accederToggle.textContent = '🔑 Acceder / Registrarse ▾';
  } catch (error) {
    if (String(error.message || '') === 'pseudonimo_taken') {
      setStatus('Ese pseudónimo ya existe. Si es tuyo, entra con la misma clave.', 'error');
    } else {
      if (usesStaticRouteMap()) {
        activateLocalSession(pseudonimo, countryCode);
        refs.pseudoInput.value = pseudonimo;
        refs.registerPseudoInput.value = pseudonimo;
        if (refs.registerKeyInput) refs.registerKeyInput.value = '';
        refs.keyInput.value = '';
        await loadAlbumData({ silent: true });
        setStatus(`Cuenta creada para ${pseudonimo} (modo local). Ya puedes entrar al álbum.`, 'success');
        alert(`✅ ¡Cuenta creada!\n\nTu cuenta "${pseudonimo}" quedó registrada.\nYa puedes abrir sobres y llenar tu álbum.`);
        refs.identityPanelWrap.hidden = true;
        refs.accederToggle.textContent = '🔑 Acceder / Registrarse ▾';
      } else {
        state.session = null;
        state.albumViewer = null;
        updateHeaderSummary();
        setStatus(`No se pudo crear la cuenta Bellator: ${error.message}.`, 'error');
      }
    }
  } finally {
    state.busy = false;
    refs.saveKeyButton.disabled = false;
    refs.registerFastButton.disabled = false;
    refs.clearKeyButton.disabled = false;
    updateHeaderSummary();
  }
}

async function clearKey() {
  state.busy = true;
  refs.saveKeyButton.disabled = true;
  refs.clearKeyButton.disabled = true;
  updateHeaderSummary();

  try {
    if (hasActiveSession() && !(state.session && state.session.local)) {
      try {
        await fetchJson(albumApiUrl('/api/album/session'), { method: 'DELETE' });
      } catch (_) {
      }
    }
    persistAlbumSessionToken('');
    state.session = null;
    state.albumViewer = null;
    state.playerPseudo = '';
    state.legacyPlayerKey = '';
    resetTradeState();
    refs.pseudoInput.value = '';
    refs.keyInput.value = '';
    localStorage.removeItem(PSEUDONIMO_STORAGE_KEY);
    localStorage.removeItem(LEGACY_PLAYER_KEY_STORAGE_KEY);
    localStorage.removeItem(LOCAL_SESSION_STORAGE_KEY);
    if (refs.identityPanelWrap) refs.identityPanelWrap.hidden = true;
    if (refs.accederToggle) refs.accederToggle.textContent = '🔑 Acceder / Registrarse ▾';
    await loadAlbumData({ silent: true });
    setStatus('Acceso Bellator cerrado. El album vuelve a modo invitado.', '');
    alert('👋 Sesión cerrada.\n\nSaliste de tu cuenta Bellator. El álbum vuelve a modo invitado.');
  } finally {
    state.busy = false;
    refs.saveKeyButton.disabled = false;
    refs.clearKeyButton.disabled = false;
    updateHeaderSummary();
  }
}

async function openPack() {
  if (state.busy || state.loading) return;

  // Se requiere iniciar sesión antes de abrir sobres / llenar el álbum.
  if (!hasAlbumIdentity()) {
    setStatus('Inicia sesión o crea tu cuenta para abrir sobres y llenar el álbum.', 'error');
    promptAlbumLogin();
    return;
  }

  const quotaBeforeOpen = dailyPackSummary();
  const useBonusPack = quotaBeforeOpen.remaining <= 0;
  if (useBonusPack && !canUseBonusPack()) {
    setStatus('Ya reclamaste tus 2 sobres gratis de las ultimas 24 horas. Espera a que se libere uno nuevo o usa un sobre extra del admin.', 'error');
    updateHeaderSummary();
    return;
  }

  if (state.catalogMode === 'preview') {
    openPreviewPack();
    return;
  }

  if (!hasAlbumIdentity()) {
    setStatus('Ingresa con tu pseudonimo y clave Bellator para abrir sobres remotos.', 'error');
    return;
  }

  state.busy = true;
  refs.introPackButton.disabled = true;
  refs.albumPackButton.disabled = true;
  refs.openAnotherButton.disabled = true;
  setStatus('Preparando sobre...', '');

  try {
    const data = await fetchJson(albumApiUrl('/api/album/open-pack'), {
      method: 'POST',
      headers: requestHeaders(true),
      body: JSON.stringify({ pack_type: 'standard', use_bonus_pack: useBonusPack }),
    });
    const dailyPacks = data && data.daily_packs ? {
      count: Math.max(0, Number(data.daily_packs.count) || 0),
      remaining: Math.max(0, Number(data.daily_packs.remaining) || 0),
      resetAt: safeText(data.daily_packs.reset_at, ''),
    } : null;
    if (state.albumViewer || useBonusPack || dailyPacks) {
      state.albumViewer = {
        authenticated: true,
        bonusPacks: Math.max(0, Number(data.remaining_bonus_packs) || 0),
        dailyPacks: dailyPacks || (state.albumViewer && state.albumViewer.dailyPacks) || { count: 0, remaining: DAILY_FREE_PACK_LIMIT, resetAt: '' },
      };
    }
    startPackCountdown();
    recordNewStickers(Number(data.new_count || 0));
    state.currentPack = Array.isArray(data.stickers) ? data.stickers.map(normalizeSticker) : [];
    state.revealPhase = 'pack';

    // Populate pending stickers for paste mechanic (los icónicos, extras y diamantes se pegan solos)
    state.currentPack.forEach((s) => {
        if (s.isNew) {
        state.pendingStickers.add(s.id);
      }
    });
    savePendingStickers();
    updatePendingTray();

    await loadAlbumData({ silent: true });
    startPackRevealFlow();
    setStatus(useBonusPack
      ? `Sobre extra consumido: ${Math.max(0, Number(data.remaining_bonus_packs) || 0)} restante(s) · ${data.new_count || 0} cromo(s) nuevos.`
      : `Sobre gratis reclamado: ${Math.max(0, Number(dailyPacks && dailyPacks.count) || 0)}/${DAILY_FREE_PACK_LIMIT} en 24 horas · ${data.new_count || 0} cromo(s) nuevos.`, 'success');
  } catch (error) {
    setStatus(`No se pudo abrir el sobre: ${error.message}.`, 'error');
  } finally {
    state.busy = false;
    updateHeaderSummary();
    if (state.currentScene === 'album') renderAlbum();
  }
}

// ─────────────────────────────────────────────────────────────────────
// Jump menu — salto directo a sección desde el pill central
// ─────────────────────────────────────────────────────────────────────

function openPageJumpMenu() {
  if (!refs.pageJumpMenu || !state.pages.length) return;
  let html = '';
  let lastGroup = '';
  const rosterTotal = rosterPageCount();
  state.pages.forEach((page, i) => {
    let label = '';
    let group = '';
    let badge = isRosterAlbumPage(page) ? `${rosterPageIndex(page)} / ${rosterTotal}` : 'Especial';
    if (page.isAlbumOverview) {
      group = 'Guía';
      label = 'Cómo funciona Bellator';
    } else if (page.isIconInfo) {
      group = 'Guía';
      label = 'Cómo funcionan los íconos';
    } else if (page.isBlackExtras) {
      group = 'Especiales';
      label = '◆ Láminas de Borde Negro';
    } else if (page.isComingSoon) {
      group = 'Cierre';
      label = 'Coming Soon';
    } else if (page.isIconic) {
      const leg = page.playerSticker;
      group = 'Íconos';
      label = `✦ ${safeText(leg && leg.displayName, 'Ícono')}`;
    } else {
      group = safeText(page.groupLabel || page.division, 'Roster');
      label = safeText(page.rawName || page.groupLabel, 'Perfil');
      const pagePending = (page.items || []).filter((s) => state.pendingStickers.has(s.id)).length;
      if (pagePending) badge = `📌 ${pagePending} por pegar`;
    }
    if (group !== lastGroup) {
      html += `<div class="jump-group-label">${escapeHtml(group)}</div>`;
      lastGroup = group;
    }
    html += `<button class="jump-item${i === state.currentPage ? ' active' : ''}" data-jump-page="${i}" type="button">${escapeHtml(label)}<span class="jump-item-badge">${escapeHtml(badge)}</span></button>`;
  });
  refs.pageJumpMenu.innerHTML = html;
  refs.pageJumpMenu.hidden = false;
  refs.pagePill.setAttribute('aria-expanded', 'true');
}

function closePageJumpMenu() {
  if (!refs.pageJumpMenu) return;
  refs.pageJumpMenu.hidden = true;
  if (refs.pagePill) refs.pagePill.setAttribute('aria-expanded', 'false');
}

function bindPasteOverlays() {
  refs.albumHost.querySelectorAll('[data-paste-id]').forEach((overlay) => {
    overlay.addEventListener('click', (e) => {
      e.stopPropagation();
      pasteStickerFromPending(overlay.getAttribute('data-paste-id'));
    });
  });
}

function jumpToPage(index) {
  closePageJumpMenu();
  if (index < 0 || index >= state.pages.length || index === state.currentPage) return;
  state.currentPage = index;
  renderAlbum();
}

function syncMobilePageTaps() {
  const prev = document.getElementById('mobile-page-prev');
  const next = document.getElementById('mobile-page-next');
  if (!prev || !next) return;
  const ready = !state.loading && state.pages.length > 0;
  prev.hidden = !ready || state.currentPage === 0;
  next.hidden = !ready || state.currentPage >= state.pages.length - 1;
}

async function navigatePage(direction) {
  if (state.busy || state.loading || !state.pages.length) return;
  const nextIndex = state.currentPage + direction;
  if (nextIndex < 0 || nextIndex >= state.pages.length) return;

  state.busy = true;
  renderAlbum();

  const host = refs.albumHost;
  const current = host.querySelector('.album-spread');
  const turningClass = direction > 0 ? 'turning-forward' : 'turning-backward';
  const outClass = direction > 0 ? 'flip-out-fwd' : 'flip-out-bwd';
  const inClass = direction > 0 ? 'flip-in-fwd' : 'flip-in-bwd';

  host.classList.add(turningClass);
  if (current) {
    current.classList.add(outClass);
    await new Promise((resolve) => setTimeout(resolve, FLIP_MS));
  }

  state.currentPage = nextIndex;
  renderAlbum();

  const incoming = host.querySelector('.album-spread');
  if (incoming) {
    incoming.classList.add(inClass);
    await new Promise((resolve) => setTimeout(resolve, FLIP_MS));
    incoming.classList.remove(inClass);
  }

  host.classList.remove(turningClass);
  state.busy = false;
  renderAlbum();
}

function switchScene(scene) {
  state.currentScene = scene;
  syncBodyScene();
  Object.entries(refs.scenes).forEach(([name, element]) => {
    element.classList.toggle('active', name === scene);
  });
  if (scene === 'album') renderAlbum();
  if (scene === 'reveal') {
    if (state.revealPhase === 'pack') renderPackOpening();
    if (state.revealPhase === 'cards') renderReveal();
    syncRevealPhase();
  }
  updateHeaderSummary();
  // Sync mobile nav active state
  const navMap = { intro: refs.mnavIntro, album: refs.mnavAlbum };
  Object.entries(navMap).forEach(([s, el]) => {
    if (el) el.classList.toggle('active', s === scene);
  });
}

function promptAlbumLogin() {
  if (state.currentScene !== 'intro') switchScene('intro');
  if (refs.identityPanelWrap) refs.identityPanelWrap.hidden = false;
  if (refs.accederToggle) refs.accederToggle.textContent = 'Cerrar acceso ▴';
  if (refs.identityPanelWrap) refs.identityPanelWrap.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function bindEvents() {
  refs.enterAlbumButton.addEventListener('click', () => {
    switchScene('album');
  });
  refs.introPackButton.addEventListener('click', openPack);
  refs.hubOpenAlbum && refs.hubOpenAlbum.addEventListener('click', () => {
    switchScene('album');
  });
  refs.hubOpenInventory && refs.hubOpenInventory.addEventListener('click', openInventoryModal);
  refs.inventoryModalClose && refs.inventoryModalClose.addEventListener('click', closeInventoryModal);
  refs.inventoryModalBackdrop && refs.inventoryModalBackdrop.addEventListener('click', (e) => {
    if (e.target === refs.inventoryModalBackdrop) closeInventoryModal();
  });
  refs.invTabAll && refs.invTabAll.addEventListener('click', () => {
    refs.invTabAll.classList.add('active');
    refs.invTabTrade && refs.invTabTrade.classList.remove('active');
    renderInventoryModal('all');
  });
  refs.invTabTrade && refs.invTabTrade.addEventListener('click', () => {
    refs.invTabTrade.classList.add('active');
    refs.invTabAll && refs.invTabAll.classList.remove('active');
    renderInventoryModal('trade');
  });
  refs.albumPackButton.addEventListener('click', openPack);
  refs.backIntroButton.addEventListener('click', () => switchScene('intro'));
  refs.saveKeyButton.addEventListener('click', syncKey);
  refs.registerFastButton.addEventListener('click', registerQuickIdentity);
  refs.clearKeyButton.addEventListener('click', clearKey);
  [refs.pseudoInput, refs.keyInput].forEach((input) => input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') syncKey();
  }));
  [refs.registerPseudoInput, refs.registerCountrySelect].forEach((input) => input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') registerQuickIdentity();
  }));

  refs.pagePrev.addEventListener('click', () => navigatePage(-1));
  refs.pageNext.addEventListener('click', () => navigatePage(1));

  const mobilePagePrev = document.getElementById('mobile-page-prev');
  const mobilePageNext = document.getElementById('mobile-page-next');
  mobilePagePrev && mobilePagePrev.addEventListener('click', () => navigatePage(-1));
  mobilePageNext && mobilePageNext.addEventListener('click', () => navigatePage(1));

  refs.pagePill.addEventListener('click', () => {
    if (refs.pageJumpMenu && !refs.pageJumpMenu.hidden) closePageJumpMenu();
    else openPageJumpMenu();
  });
  document.addEventListener('click', (e) => {
    if (refs.pageJumpMenu && !refs.pageJumpMenu.hidden && refs.pagePillWrap && !refs.pagePillWrap.contains(e.target)) closePageJumpMenu();
  });
  refs.pageJumpMenu.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-jump-page]');
    if (!btn) return;
    jumpToPage(Number(btn.dataset.jumpPage));
  });
  refs.packSceneButton.addEventListener('click', playPackOpening);

  refs.revealPrev.addEventListener('click', () => {
    if (state.revealIndex <= 0) return;
    state.revealIndex -= 1;
    renderReveal();
  });
  refs.revealNext.addEventListener('click', () => {
    if (state.revealIndex >= state.currentPack.length - 1) return;
    state.revealIndex += 1;
    renderReveal();
  });
  refs.openAnotherButton.addEventListener('click', openPack);
  refs.revealAlbumButton.addEventListener('click', () => switchScene('album'));
  refs.revealPasteButton.addEventListener('click', goToPasteScene);
  refs.revealDownloadBtn.addEventListener('click', () => {
    const card = refs.revealCardHost;
    if (!card) return;
    const sticker = state.currentPack[state.revealIndex];
    const slug = sticker ? safeText(sticker.displayName, 'cromo').toLowerCase().replace(/\s+/g, '-') : 'cromo';
    downloadStickerCard(card, `cromo-${slug}.png`);
  });
  refs.accessOpenPanel.addEventListener('click', () => {
    promptAlbumLogin();
    setStatus(hasAlbumIdentity() ? 'Gestiona tu acceso Bellator desde este panel.' : 'Entra o crea tu perfil Bellator desde este panel.', '');
  });
  refs.hubLogout.addEventListener('click', clearKey);
  refs.hubOpenTrade.addEventListener('click', openTradeModal);
  refs.tradeModalClose.addEventListener('click', closeTradeModal);
  refs.tradeModalBackdrop.addEventListener('click', (e) => {
    if (e.target === refs.tradeModalBackdrop) closeTradeModal();
  });
  refs.tradeTabOffer.addEventListener('click', () => {
    refs.tradeTabOffer.classList.add('active');
    refs.tradeTabImport.classList.remove('active');
    refs.tradePanelOffer.classList.add('active');
    refs.tradePanelImport.classList.remove('active');
    renderTradeOfferPanel();
  });
  refs.tradeTabImport.addEventListener('click', () => {
    refs.tradeTabImport.classList.add('active');
    refs.tradeTabOffer.classList.remove('active');
    refs.tradePanelImport.classList.add('active');
    refs.tradePanelOffer.classList.remove('active');
    renderTradeBoard();
  });
  if (refs.tradeTargetSelect) refs.tradeTargetSelect.addEventListener('change', () => {
    state.tradeTargetPlayer = safeText(refs.tradeTargetSelect.value, '');
    renderTradeOfferPanel();
  });
  refs.tradeCopyCodeButton.addEventListener('click', async () => {
    const payload = publishTradeRequest();
    if (!payload) {
      const targetPlayer = safeText(state.tradeTargetPlayer, '');
      const message = !hasActiveSession()
        ? 'Activa una sesión Bellator para publicar tu solicitud.'
        : !shouldUseRemoteAlbumApi()
          ? 'El intercambio real no funciona en este modo local del álbum.'
          : !targetPlayer
            ? 'Elige primero a qué jugador quieres mandarle la solicitud.'\r
            : 'Selecciona al menos un cromo para ofrecer (repetida o especial) o un faltante para pedir.';
      setStatus(message, 'error');
      return;
    }
    refs.tradeCopyCodeButton.disabled = true;
    const previousText = refs.tradeCopyCodeButton.textContent;
    refs.tradeCopyCodeButton.textContent = 'Publicando...';
    try {
      const data = await fetchJson(albumApiUrl('/api/album/trades'), {
        method: 'POST',
        headers: requestHeaders(true),
        body: JSON.stringify(payload),
      });
      state.tradePublishedRequests = Array.isArray(data && data.requests) ? data.requests : [];
      refs.tradeCopyCodeButton.textContent = '¡Solicitud enviada!';
      setTimeout(() => { refs.tradeCopyCodeButton.textContent = previousText; }, 2200);
      refs.tradeTabImport.click();
      renderTradeBoard();
      setTradeFeedback(`Solicitud enviada a ${payload.targetPlayer}. Solo ese perfil podrá aceptarla.`, 'success');
      setStatus(`Tu solicitud quedó enviada a ${payload.targetPlayer}. Solo ese perfil podrá aceptarla.`, 'success');
    } catch (error) {
      refs.tradeCopyCodeButton.textContent = previousText;
      setTradeFeedback(`No se pudo publicar la solicitud: ${error.message}.`, 'error');
      setStatus(`No se pudo publicar la solicitud: ${error.message}.`, 'error');
    } finally {
      refs.tradeCopyCodeButton.disabled = false;
    }
  });
  refs.tradeDuplicateList.addEventListener('click', (event) => {
    const button = event.target.closest('[data-trade-offer-id]');
    if (!button) return;
    toggleTradeOfferSelection(button.getAttribute('data-trade-offer-id'));
  });
  refs.tradeWantList.addEventListener('click', (event) => {
    const button = event.target.closest('[data-trade-want-id]');
    if (!button) return;
    toggleTradeWantSelection(button.getAttribute('data-trade-want-id'));
  });
  refs.tradeWantFilter.addEventListener('input', () => {
    state.tradeWantFilter = refs.tradeWantFilter.value || '';
    renderTradeOfferPanel();
  });
  refs.tradeBoardFilterOpen.addEventListener('click', () => {
    state.tradeBoardFilter = 'open';
    renderTradeBoard();
  });
  refs.tradeBoardFilterAll.addEventListener('click', () => {
    state.tradeBoardFilter = 'all';
    renderTradeBoard();
  });
  refs.tradeOfferResult.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-trade-accept-id]');
    if (!button) return;
    const tradeId = safeText(button.getAttribute('data-trade-accept-id'), '');
    if (!tradeId || !hasActiveSession()) return;
    button.disabled = true;
    const previousText = button.textContent;
    button.textContent = 'Canjeando...';
    try {
      const data = await fetchJson(albumApiUrl('/api/album/trades/accept'), {
        method: 'POST',
        headers: requestHeaders(true),
        body: JSON.stringify({ id: tradeId }),
      });
      state.tradePublishedRequests = Array.isArray(data && data.requests) ? data.requests : [];
      await loadAlbumData({ silent: true });
      renderTradeBoard();
      renderTradeOfferPanel();
      setTradeFeedback('Intercambio completado y sincronizado. Las piezas ya se restaron y sumaron en ambos inventarios.', 'success');
      setStatus('Intercambio completado. Tu inventario y el muro ya quedaron actualizados.', 'success');
    } catch (error) {
      button.disabled = false;
      button.textContent = previousText;
      setTradeFeedback(`No se pudo completar el intercambio: ${error.message}.`, 'error');
      setStatus(`No se pudo completar el intercambio: ${error.message}.`, 'error');
    }
  });
  if (refs.missionEditorSave) refs.missionEditorSave.addEventListener('click', saveMissionEditor);
  if (refs.missionEditorCancel) refs.missionEditorCancel.addEventListener('click', closeMissionEditor);
  if (refs.missionEditorReset) refs.missionEditorReset.addEventListener('click', resetMissionEditor);
  refs.soundtrackSelect.addEventListener('change', () => applySoundtrackSelection(refs.soundtrackSelect.value));
  refs.soundtrackToggle.addEventListener('click', toggleSoundtrack);
  refs.soundtrackStop.addEventListener('click', stopSoundtrack);

  refs.accederToggle.addEventListener('click', () => {
    refs.identityPanelWrap.hidden = !refs.identityPanelWrap.hidden;
    refs.accederToggle.textContent = refs.identityPanelWrap.hidden
      ? 'Acceder con tu clave Bellator ▾'
      : 'Cerrar acceso ▴';
  });

  refs.mnavIntro.addEventListener('click', () => switchScene('intro'));
  refs.mnavPack.addEventListener('click', () => {
    if (state.loading || state.busy) return;
    refs.introPackButton.click();
  });
  refs.mnavAlbum.addEventListener('click', () => switchScene('album'));
  refs.mnavTrade.addEventListener('click', openTradeModal);

  refs.overlayClose.addEventListener('click', closeOverlay);
  refs.overlay.addEventListener('click', (event) => {
    if (event.target === refs.overlay) closeOverlay();
  });
  refs.overlayPrev.addEventListener('click', () => {
    if (state.overlayIndex <= 0) return;
    state.overlayIndex -= 1;
    renderOverlay();
  });
  refs.overlayNext.addEventListener('click', () => {
    if (state.overlayIndex >= state.overlayPool.length - 1) return;
    state.overlayIndex += 1;
    renderOverlay();
  });

  window.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      if (refs.inventoryModalBackdrop && refs.inventoryModalBackdrop.classList.contains('show')) {
        closeInventoryModal();
        return;
      }
      if (refs.tradeModalBackdrop.classList.contains('show')) {
        closeTradeModal();
        return;
      }
      if (refs.overlay.classList.contains('show')) {
        closeOverlay();
        return;
      }
      if (state.currentScene === 'reveal') {
        switchScene('album');
      }
    }
    if (state.currentScene === 'reveal' && state.revealPhase === 'pack' && (event.key === 'Enter' || event.key === ' ')) {
      event.preventDefault();
      playPackOpening();
    }
    if (state.currentScene === 'album') {
      if (event.key === 'ArrowRight') navigatePage(1);
      if (event.key === 'ArrowLeft') navigatePage(-1);
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      refreshAlbumViewerSummary({ silent: true }).catch(() => {});
    }
  });

  window.addEventListener('focus', () => {
    refreshAlbumViewerSummary({ silent: true }).catch(() => {});
  });

  let touchStartX = 0;
  let touchStartY = 0;
  refs.albumHost.addEventListener('touchstart', (event) => {
    touchStartX = event.touches[0].clientX;
    touchStartY = event.touches[0].clientY;
  }, { passive: true });

  refs.albumHost.addEventListener('touchend', (event) => {
    if (state.currentScene !== 'album') return;
    const dx = event.changedTouches[0].clientX - touchStartX;
    const dy = event.changedTouches[0].clientY - touchStartY;
    if (Math.abs(dx) < 48 || Math.abs(dx) < Math.abs(dy) * 1.35) return;
    navigatePage(dx < 0 ? 1 : -1);
  }, { passive: true });
}

// ─────────────────────────────────────────────────────────────────────
// Pending stickers localStorage helpers
// ─────────────────────────────────────────────────────────────────────

function savePendingStickers() {
  localStorage.setItem(pendingStickerStorageKey(), JSON.stringify([...state.pendingStickers]));
}

function loadPendingStickers() {
  try {
    const arr = JSON.parse(localStorage.getItem(pendingStickerStorageKey()) || '[]');
    return new Set(Array.isArray(arr) ? arr.filter((v) => typeof v === 'string') : []);
  } catch (_) {
    return new Set();
  }
}

function updatePendingTray() {
  const count = state.pendingStickers.size;
  refs.pendingTray.classList.toggle('visible', count > 0);
  refs.pendingCount.textContent = String(count);
}

function pasteStickerFromPending(stickerId) {
  if (!state.pendingStickers.has(stickerId)) return;
  state.pendingStickers.delete(stickerId);
  savePendingStickers();
  updatePendingTray();

  // Animate the slot in-place without full re-render
  const slotId = CSS && CSS.escape ? CSS.escape(stickerId) : stickerId.replace(/[^\w-]/g, '_');
  const slot = refs.albumHost.querySelector(`[data-sticker-id="${slotId}"]`) ||
    refs.albumHost.querySelector(`button[data-pending]`);
  const targetSlot = refs.albumHost.querySelector(`[data-sticker-id="${stickerId.replace(/"/g, '&quot;')}"]`);
  if (targetSlot) {
    const overlay = targetSlot.querySelector('[data-paste-id]');
    if (overlay) overlay.remove();
    targetSlot.removeAttribute('data-pending');
    targetSlot.classList.add('paste-done');
    setTimeout(() => targetSlot.classList.remove('paste-done'), 500);
  }

  updateHeaderSummary();
}

function goToPasteScene() {
  switchScene('album');
  if (state.pendingStickers.size === 0) return;
  const firstId = [...state.pendingStickers][0];
  const pageIndex = state.pages.findIndex((page) =>
    page.items.some((item) => item.id === firstId)
  );
  if (pageIndex >= 0 && pageIndex !== state.currentPage) {
    state.currentPage = pageIndex;
    renderAlbum();
  }
}

// ─────────────────────────────────────────────────────────────────────
// Trade / Intercambio
// ─────────────────────────────────────────────────────────────────────

function tradeOfferInventory() {
  return state.stickers
    .filter((sticker) => sticker.quantity > 1)
    .sort((a, b) => (b.quantity - a.quantity) || (a.groupOrder - b.groupOrder) || (a.slotNumber - b.slotNumber));
}

function tradeMissingInventory() {
  return state.stickers
    .filter((sticker) => !sticker.collected)
    .sort((a, b) => (a.groupOrder - b.groupOrder) || (a.slotNumber - b.slotNumber));
}

function pruneTradeSelections() {
  const offerIds = new Set(tradeOfferInventory().map((sticker) => sticker.id));
  const wantIds = new Set(tradeMissingInventory().map((sticker) => sticker.id));
  state.tradeOfferSelection = new Set([...state.tradeOfferSelection].filter((id) => offerIds.has(id)));
  state.tradeWantSelection = new Set([...state.tradeWantSelection].filter((id) => wantIds.has(id)));
}

function toggleTradeOfferSelection(stickerId) {
  if (!stickerId) return;
  if (state.tradeOfferSelection.has(stickerId)) state.tradeOfferSelection.delete(stickerId);
  else state.tradeOfferSelection.add(stickerId);
  renderTradeOfferPanel();
}

function toggleTradeWantSelection(stickerId) {
  if (!stickerId) return;
  if (state.tradeWantSelection.has(stickerId)) state.tradeWantSelection.delete(stickerId);
  else state.tradeWantSelection.add(stickerId);
  renderTradeOfferPanel();
}

// ── Inventory modal ──────────────────────────────────────────
function inventoryCardHtml(sticker) {
  const name = escapeHtml(sticker.displayName || sticker.id || '?');
  const rarity = sticker.rarity || 'comun';
  const isPending = state.pendingStickers.has(sticker.id);
  const isExtra = sticker.quantity > 1;
  const isForTrade = isPending || isExtra;
  const initials = (sticker.displayName || '?')
    .replace(/[^\w\s]/g, '').split(/\s+/).filter(Boolean)
    .slice(0, 2).map((w) => w[0].toUpperCase()).join('') || '?';
  const photoContent = sticker.imageUrl
    ? `<img src="${escapeHtml(sticker.imageUrl)}" alt="${name}" loading="lazy" onerror="this.parentElement.classList.add('no-photo');this.parentElement.innerHTML='<span>${escapeHtml(initials)}</span>';">`
    : `<span>${escapeHtml(initials)}</span>`;
  const photoClass = sticker.imageUrl ? 'inv-card-photo' : 'inv-card-photo no-photo';
  const badgeHtml = isPending
    ? '<div class="inv-card-pending">Sin pegar</div>'
    : (isExtra ? `<div class="inv-card-trade">+${sticker.quantity - 1} extra</div>` : '');
  const qtyHtml = sticker.quantity > 1 ? `<div class="inv-card-qty">×${sticker.quantity}</div>` : '';
  return `<div class="inv-card rarity-${escapeHtml(rarity)}${isForTrade ? ' tradeable' : ''}">
    <div class="${photoClass}">${photoContent}</div>
    <div class="inv-card-overlay" aria-hidden="true"></div>
    ${qtyHtml}
    ${badgeHtml}
    <div class="inv-card-footer">
      <div class="inv-card-name">${name}</div>
      <div class="inv-card-rarity">${escapeHtml(rarityLabel(rarity))}</div>
    </div>
  </div>`;
}

function renderInventoryModal(tab) {
  const host = refs.invGridHost;
  const statsEl = refs.invStats;
  if (!host) return;

  const collected = state.stickers.filter((s) => s.quantity > 0);
  const forTrade = collected.filter((s) => state.pendingStickers.has(s.id) || s.quantity > 1);
  const stickersToShow = tab === 'trade' ? forTrade : collected;

  // Stats strip
  if (statsEl) {
    const total = state.stickers.length;
    const owned = collected.length;
    const pending = state.pendingStickers.size;
    const offers = forTrade.length;
    statsEl.innerHTML = [
      `<div class="inv-stat-chip"><strong>${owned}</strong> / ${total} cromos</div>`,
      pending ? `<div class="inv-stat-chip"><strong>${pending}</strong> sin pegar</div>` : '',
      offers ? `<div class="inv-stat-chip"><strong>${offers}</strong> para canje</div>` : '',
    ].join('');
  }

  if (!stickersToShow.length) {
    host.innerHTML = tab === 'trade'
      ? '<div class="inv-empty">No tienes cromos disponibles para intercambio aún.<br>Abre sobres, consigue duplicados o tendrás cromos sin pegar.</div>'
      : '<div class="inv-empty">Abre sobres para comenzar tu colección.</div>';
    return;
  }

  const rarityOrder = ['esmeralda','diamante','iconico','legendario','epico','raro','comun','blackborder'];
  const rarityTitles = {
    esmeralda: '🟢 Esmeraldas', diamante: '◈ Diamantes', iconico:'\u2736 Icónicos', legendario:'◈ Legendarios', epico:'⚡ Épicos',
    raro:'◆ Raros', comun:'· Comunes', blackborder:'◆ Borde Negro',
  };
  const groups = {};
  stickersToShow.forEach((s) => {
    const k = s.rarity || 'comun';
    if (!groups[k]) groups[k] = [];
    groups[k].push(s);
  });

  let html = '';
  rarityOrder.forEach((r) => {
    if (!groups[r] || !groups[r].length) return;
    html += `<section class="inv-section">
      <div class="inv-section-header rarity-${r}">
        <span>${escapeHtml(rarityTitles[r] || r)}</span>
        <span class="inv-section-count">${groups[r].length}</span>
      </div>
      <div class="inv-grid">${groups[r].map(inventoryCardHtml).join('')}</div>
    </section>`;
  });
  host.innerHTML = html;
}

function openInventoryModal() {
  if (!hasAlbumIdentity()) {
    promptAlbumLogin();
    setStatus('Inicia sesión para ver tu inventario.', 'error');
    return;
  }
  // Set active tab to all
  refs.invTabAll && refs.invTabAll.classList.add('active');
  refs.invTabTrade && refs.invTabTrade.classList.remove('active');
  renderInventoryModal('all');
  refs.inventoryModalBackdrop && refs.inventoryModalBackdrop.classList.add('show');
}

function closeInventoryModal() {
  refs.inventoryModalBackdrop && refs.inventoryModalBackdrop.classList.remove('show');
}

function openTradeModal() {
  if (!hasActiveSession()) {
    promptAlbumLogin();
    setStatus('Inicia sesión para abrir el mercado Bellator y ver tu inventario real.', 'error');
    return;
  }
  if (!shouldUseRemoteAlbumApi()) {
    setStatus('El intercambio real solo funciona cuando el álbum está conectado al backend Bellator.', 'error');
    return;
  }
  refs.tradeModalBackdrop.classList.add('show');
  refs.tradeTabOffer.classList.add('active');
  refs.tradeTabImport.classList.remove('active');
  refs.tradePanelOffer.classList.add('active');
  refs.tradePanelImport.classList.remove('active');
  state.tradeTargetsLoading = true;
  renderTradeOfferPanel();
  renderTradeBoard();
  fetchTradeTargets().then(() => {
    renderTradeOfferPanel();
  }).catch((error) => {
    state.tradeTargets = [];
    state.tradeTargetPlayer = '';
    renderTradeOfferPanel();
    setStatus(`No se pudo cargar la lista de jugadores del álbum: ${error.message}.`, 'error');
  });
  fetchTradeBoard().then(() => {
    renderTradeBoard();
  }).catch((error) => {
    state.tradePublishedRequests = [];
    renderTradeBoard();
    setStatus(`No se pudo cargar el mercado real: ${error.message}.`, 'error');
  });
}

function closeTradeModal() {
  refs.tradeModalBackdrop.classList.remove('show');
}

function renderTradeBoard() {
  const requests = loadTradeRequests()
    .filter((request) => state.tradeBoardFilter === 'all' ? true : safeText(request.status, 'open') === 'open')
    .sort((left, right) => safeText(right.createdAt, '').localeCompare(safeText(left.createdAt, '')));

  const currentPseudo = safeText(state.session && state.session.pseudonimo, '');
  const myDuplicateIds = new Set(tradeOfferInventory().map((sticker) => sticker.id));
  const myMissingIds = new Set(tradeMissingInventory().map((sticker) => sticker.id));
  const isOwnRequest = (request) => sameTradePlayer(request.player, currentPseudo);
  const isIncomingRequest = (request) => sameTradePlayer(request.targetPlayer, currentPseudo);
  const incoming = requests.filter((request) => isIncomingRequest(request));
  const mine = requests.filter((request) => isOwnRequest(request));
  const board = state.tradeBoardFilter === 'all'
    ? requests.filter((request) => !isOwnRequest(request) && !isIncomingRequest(request))
    : [];

  refs.tradeBoardStatus.textContent = state.tradeBoardFilter === 'all' ? 'Todas' : 'Abiertas';
  refs.tradeBoardCount.textContent = String(requests.length);
  refs.tradeBoardHelpful.textContent = String(incoming.length);
  refs.tradeBoardMatch.textContent = String(mine.length);
  refs.tradeBoardMeta.textContent = requests.length
    ? state.tradeBoardFilter === 'all'
      ? `Hay ${incoming.length} para ti, ${mine.length} tuya${mine.length === 1 ? '' : 's'} y ${board.length} entre otros perfiles.`
      : `Hay ${incoming.length} para ti y ${mine.length} tuya${mine.length === 1 ? '' : 's'} abiertas ahora mismo.`
    : 'Todavía no hay solicitudes dirigidas publicadas en este entorno.';
  refs.tradeBoardFilterOpen.classList.toggle('active', state.tradeBoardFilter === 'open');
  refs.tradeBoardFilterAll.classList.toggle('active', state.tradeBoardFilter === 'all');

  if (!requests.length) {
    refs.tradeOfferResult.innerHTML = '<div class="trade-empty">Todavía no hay solicitudes dirigidas. Envía la tuya a otro jugador y abrirás la bandeja real de este álbum.</div>';
    return;
  }

  if (!incoming.length && !mine.length && state.tradeBoardFilter !== 'all') {
    refs.tradeOfferResult.innerHTML = '<div class="trade-empty">No tienes solicitudes abiertas dirigidas a tu perfil en este momento. Cambia a "Todas" si quieres revisar intercambios entre otros jugadores.</div>';
    return;
  }

  const renderRequestCard = (request) => {
    const offerItems = Array.isArray(request.offer) ? request.offer : [];
    const wantItems = Array.isArray(request.want) ? request.want : [];
    const helpsMe = offerItems.filter((item) => myMissingIds.has(item.id)).length;
    const iCanHelp = wantItems.filter((item) => myDuplicateIds.has(item.id)).length;
    const ownRequest = isOwnRequest(request);
    const incomingRequest = isIncomingRequest(request);
    const targetPlayer = safeText(request.targetPlayer, 'otro perfil');
    const canAccept = incomingRequest && safeText(request.status, 'open') === 'open';
    const sectionCopy = ownRequest
      ? `Solicitud enviada a ${targetPlayer}.`
      : incomingRequest
        ? `${safeText(request.player, 'Coleccionista')} te la mandó directamente.`
        : `${safeText(request.player, 'Coleccionista')} se la mandó a ${targetPlayer}.`;
    return `
      <div class="trade-board-card">
        <div class="trade-board-head">
          <div>
            <div class="trade-board-title">${escapeHtml(safeText(request.player, 'Coleccionista'))}</div>
            <div class="trade-board-copy">${escapeHtml(sectionCopy)}</div>
          </div>
          <div class="trade-board-tags">
            <div class="trade-sticker-badge">Para ${escapeHtml(targetPlayer)}</div>
            <div class="trade-sticker-badge">Ofrece ${offerItems.length}</div>
            <div class="trade-sticker-badge">Busca ${wantItems.length}</div>
            <div class="trade-sticker-badge">Te sirve ${helpsMe}</div>
            <div class="trade-sticker-badge">Le sirves ${iCanHelp}</div>
            ${canAccept ? `<button class="trade-select-button active" data-trade-accept-id="${escapeHtml(safeText(request.id, ''))}" type="button">Aceptar intercambio</button>` : ''}
          </div>
        </div>
        ${offerItems.length ? `
          <div class="trade-section-head"><strong>Ofrece</strong><span>${escapeHtml(safeText(request.player, 'Perfil'))} pone estas piezas en la solicitud.</span></div>
          <div class="trade-duplicate-list">
            ${offerItems.map((item) => `
              <div class="trade-sticker-row">
                <div>
                  <div class="trade-sticker-name">${escapeHtml(safeText(item.name, '?'))}</div>
                  <div class="trade-sticker-meta">${escapeHtml(safeText(item.group, ''))} · ${escapeHtml(safeText(item.rarity, ''))}</div>
                  ${myMissingIds.has(item.id) ? '<div class="trade-match-note">Te falta en tu álbum.</div>' : ''}
                </div>
                <div class="trade-sticker-actions">
                  <div class="trade-sticker-badge">x${Number(item.extra) || 1}</div>
                  ${item.pending ? '<div class="trade-sticker-badge">Pendiente</div>' : ''}
                </div>
              </div>`).join('')}
          </div>` : ''}
        ${wantItems.length ? `
          <div class="trade-section-head"><strong>Busca</strong><span>Estas son las piezas que le faltan.</span></div>
          <div class="trade-duplicate-list">
            ${wantItems.map((item) => `
              <div class="trade-sticker-row">
                <div>
                  <div class="trade-sticker-name">${escapeHtml(safeText(item.name, '?'))}</div>
                  <div class="trade-sticker-meta">${escapeHtml(safeText(item.group, ''))} · ${escapeHtml(safeText(item.rarity, ''))}</div>
                </div>
                ${myDuplicateIds.has(item.id) ? '<div class="trade-sticker-badge">Tú la tienes repetida</div>' : ''}
              </div>`).join('')}
          </div>` : ''}
      </div>`;
  };

  const sections = [];
  if (incoming.length) {
    sections.push(`
      <div class="trade-section-head"><strong>Solicitudes para ti</strong><span>Solo ${escapeHtml(currentPlayerLabel())} puede aceptarlas.</span></div>
      <div class="trade-duplicate-list">
        ${incoming.map((request) => renderRequestCard(request)).join('')}
      </div>`);
  }
  if (mine.length) {
    sections.push(`
      <div class="trade-section-head"><strong>Tus solicitudes enviadas</strong><span>Ya quedaron dirigidas al jugador que elegiste.</span></div>
      <div class="trade-duplicate-list">
        ${mine.map((request) => renderRequestCard(request)).join('')}
      </div>`);
  }
  if (board.length) {
    sections.push(`
      <div class="trade-section-head"><strong>Tablero general</strong><span>Solicitudes dirigidas entre otros perfiles del álbum.</span></div>
      <div class="trade-duplicate-list">
        ${board.map((request) => renderRequestCard(request)).join('')}
      </div>`);
  }

  refs.tradeOfferResult.innerHTML = sections.join('') || '<div class="trade-empty">No hay solicitudes visibles con el filtro actual.</div>';
}

function renderTradeOfferPanel() {
  pruneTradeSelections();
  const duplicates = tradeOfferInventory();
  const missing = tradeMissingInventory();
  const wantFilter = safeText(state.tradeWantFilter, '').toLowerCase();
  const filteredMissing = missing.filter((sticker) => {
    if (!wantFilter) return true;
    const haystack = [
      safeText(sticker.displayName, ''),
      safeText(sticker.groupLabel, ''),
      safeText(sticker.playerPseudo, ''),
      formatSlotLabel(sticker.slotNumber),
    ].join(' ').toLowerCase();
    return haystack.includes(wantFilter);
  });
  const visibleMissing = filteredMissing.slice(0, wantFilter ? 32 : 18);

  if (refs.tradeWantFilter && refs.tradeWantFilter.value !== state.tradeWantFilter) {
    refs.tradeWantFilter.value = state.tradeWantFilter;
  }
  if (refs.tradeBuilderPlayer) refs.tradeBuilderPlayer.textContent = currentPlayerLabel();
  if (refs.tradeBuilderPending) refs.tradeBuilderPending.textContent = String(state.pendingStickers.size);
  if (refs.tradeBuilderOfferCount) refs.tradeBuilderOfferCount.textContent = String(state.tradeOfferSelection.size);
  if (refs.tradeBuilderWantCount) refs.tradeBuilderWantCount.textContent = String(state.tradeWantSelection.size);

  if (refs.tradeTargetSelect) {
    if (state.tradeTargetsLoading) {
      refs.tradeTargetSelect.innerHTML = '<option value="">Cargando jugadores...</option>';
      refs.tradeTargetSelect.disabled = true;
    } else if (state.tradeTargets.length) {
      refs.tradeTargetSelect.innerHTML = state.tradeTargets.map((pseudo) => `<option value="${escapeHtml(pseudo)}">${escapeHtml(pseudo)}</option>`).join('');
      const selected = state.tradeTargets.find((pseudo) => sameTradePlayer(pseudo, state.tradeTargetPlayer)) || state.tradeTargets[0] || '';
      refs.tradeTargetSelect.value = selected;
      state.tradeTargetPlayer = selected;
      refs.tradeTargetSelect.disabled = false;
    } else {
      refs.tradeTargetSelect.innerHTML = '<option value="">No hay otros jugadores registrados todavía</option>';
      refs.tradeTargetSelect.disabled = true;
    }
  }
  if (refs.tradeTargetHint) {
    refs.tradeTargetHint.textContent = state.tradeTargetsLoading
      ? 'Buscando perfiles Bellator disponibles...'
      : state.tradeTargetPlayer
        ? `La solicitud le llegará a ${state.tradeTargetPlayer} y solo ese perfil podrá aceptarla.`
        : 'Primero elige a qué jugador se la quieres mandar.';
  }

  if (!hasActiveSession()) {
    refs.tradeDuplicateList.innerHTML = '<div class="trade-empty">Activa una sesión Bellator para publicar solicitudes reales en el mercado.</div>';
    if (refs.tradeWantList) refs.tradeWantList.innerHTML = '<div class="trade-empty">Cuando entres con tu perfil verás aquí tus faltantes reales y podrás pedirlos.</div>';
    if (refs.tradeCopyCodeButton) refs.tradeCopyCodeButton.disabled = true;
    if (refs.tradeWantFilter) refs.tradeWantFilter.disabled = true;
    if (refs.tradeTargetSelect) refs.tradeTargetSelect.disabled = true;
    return;
  }

  if (!shouldUseRemoteAlbumApi()) {
    refs.tradeDuplicateList.innerHTML = '<div class="trade-empty">Este modo local del álbum no puede enviar solicitudes reales. Usa el álbum conectado al backend Bellator.</div>';
    if (refs.tradeWantList) refs.tradeWantList.innerHTML = '<div class="trade-empty">Cuando abras el álbum conectado al backend podrás pedir cromos a otros perfiles reales.</div>';
    if (refs.tradeCopyCodeButton) refs.tradeCopyCodeButton.disabled = true;
    if (refs.tradeWantFilter) refs.tradeWantFilter.disabled = true;
    if (refs.tradeTargetSelect) refs.tradeTargetSelect.disabled = true;
    if (refs.tradeTargetHint) refs.tradeTargetHint.textContent = 'El intercambio real necesita sesión Bellator y conexión al backend.';
    return;
  }

  if (refs.tradeCopyCodeButton) refs.tradeCopyCodeButton.disabled = state.tradeTargetsLoading || !state.tradeTargets.length;
  if (refs.tradeWantFilter) refs.tradeWantFilter.disabled = false;

  if (!duplicates.length) {
    refs.tradeDuplicateList.innerHTML = '<div class="trade-empty">Todavía no tienes repetidas. Igual puedes crear una petición real seleccionando cromos faltantes abajo.</div>';
  } else {
    refs.tradeDuplicateList.innerHTML = duplicates.map((sticker) => {
      const selected = state.tradeOfferSelection.has(sticker.id);
      const pendingNote = state.pendingStickers.has(sticker.id)
        ? '<div class="trade-match-note">Aún no está pegado, pero ya cuenta en tu inventario para intercambio.</div>'
        : '';
      const thumbImg = sticker.imageUrl
        ? `<img src="${escapeHtml(sticker.imageUrl)}" alt="${escapeHtml(sticker.displayName)}" loading="lazy" onerror="const p=this.parentElement;if(!p)return;p.classList.add('no-photo');p.innerHTML='?';this.remove()">`
        : '';
      return `
        <div class="trade-sticker-row${selected ? ' selected' : ''}">
          <div class="trade-sticker-thumb rarity-${escapeHtml(sticker.rarity)}">${thumbImg || '?'}<div class="thumb-rarity">${escapeHtml(rarityLabel(sticker.rarity).slice(0,3))}</div></div>
          <div class="trade-sticker-info">
            <div class="trade-sticker-name">${escapeHtml(sticker.displayName)}</div>
            <div class="trade-sticker-meta">${escapeHtml(sticker.groupLabel)} · ${formatSlotLabel(sticker.slotNumber)}</div>
            ${pendingNote}
          </div>
          <div class="trade-sticker-actions">
            <div class="trade-sticker-badge">×${sticker.quantity - 1} extra</div>
            <button class="trade-select-button${selected ? ' active' : ''}" data-trade-offer-id="${escapeHtml(sticker.id)}" type="button">${selected ? 'Quitar' : 'Ofrecer'}</button>
          </div>
        </div>`;
    }).join('');
  }

  if (!refs.tradeWantList) return;
  if (!visibleMissing.length) {
    refs.tradeWantList.innerHTML = `<div class="trade-empty">${wantFilter ? 'No coincide ningún faltante con esa búsqueda.' : 'No tienes faltantes pendientes.'}</div>`;
  } else {
    refs.tradeWantList.innerHTML = visibleMissing.map((sticker) => {
      const selected = state.tradeWantSelection.has(sticker.id);
      const thumbImg = sticker.imageUrl
        ? `<img src="${escapeHtml(sticker.imageUrl)}" alt="${escapeHtml(sticker.displayName)}" loading="lazy" onerror="const p=this.parentElement;if(!p)return;p.classList.add('no-photo');p.innerHTML='?';this.remove()">`
        : '';
      return `
        <div class="trade-sticker-row${selected ? ' selected' : ''}">
          <div class="trade-sticker-thumb rarity-${escapeHtml(sticker.rarity)}">${thumbImg || '?'}<div class="thumb-rarity">${escapeHtml(rarityLabel(sticker.rarity).slice(0,3))}</div></div>
          <div class="trade-sticker-info">
            <div class="trade-sticker-name">${escapeHtml(sticker.displayName)}</div>
            <div class="trade-sticker-meta">${escapeHtml(sticker.groupLabel)} · ${formatSlotLabel(sticker.slotNumber)}</div>
          </div>
          <div class="trade-sticker-actions">
            <button class="trade-select-button${selected ? ' active' : ''}" data-trade-want-id="${escapeHtml(sticker.id)}" type="button">${selected ? 'Añadido' : 'Pedir'}</button>
          </div>
        </div>`;
    }).join('');
  }
}

function publishTradeRequest() {
  const payload = buildTradeRequestPayload();
  if (!payload) return false;
  return payload;
}

/* ────────────────────────────────────────────────────────
   DOWNLOAD STICKER AS PNG — lazy-loads html2canvas from CDN
   ──────────────────────────────────────────────────────── */
async function downloadStickerCard(cardEl, filename) {
  // Lazy-load html2canvas only when needed
  if (typeof html2canvas === 'undefined') {
    try {
      await new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js';
        s.crossOrigin = 'anonymous';
        s.onload = resolve;
        s.onerror = reject;
        document.head.appendChild(s);
      });
    } catch {
      alert('No se pudo cargar la herramienta. Comprueba tu conexión e intenta de nuevo.');
      return;
    }
  }
  try {
    const canvas = await html2canvas(cardEl, {
      scale: 3,
      useCORS: true,
      allowTaint: true,
      backgroundColor: null,
      logging: false,
    });
    const link = document.createElement('a');
    link.download = filename || 'cromo-bellator.png';
    link.href = canvas.toDataURL('image/png');
    link.click();
  } catch (err) {
    console.error('downloadStickerCard error:', err);
    alert('Error al generar la imagen. Si usas Safari, prueba en Chrome.');
  }
}

/* ────────────────────────────────────────────────────────
   CUSTOM STICKER CREATOR — build your own cromo
   ──────────────────────────────────────────────────────── */
function initCreator() {
  const imgInput = document.getElementById('creator-img-input');
  const uploadLabel = document.getElementById('creator-upload-label');
  const uploadZone = document.getElementById('creator-upload-zone');
  const nameInput = document.getElementById('creator-name');
  const subtitleInput = document.getElementById('creator-subtitle');
  const countrySelect = document.getElementById('creator-country');
  const downloadBtn = document.getElementById('creator-download-btn');
  const previewWrap = document.getElementById('creator-preview-wrap');

  if (!imgInput || !previewWrap) return; // DOM not ready / creator not in page

  let creatorImageDataUrl = '';

  function buildPreview() {
    const name = nameInput.value.trim() || 'Tu Nombre';
    const subtitle = subtitleInput.value.trim() || 'Bellator 2026';
    const rarity = 'comun';
    const code = countrySelect.value;
    const flag = code ? countryFlag(code) : '';
    const flagImg = code ? countryFlagImg(code) : '';

    const photo = creatorImageDataUrl
      ? `<div class="sticker-photo"><img src="${creatorImageDataUrl}" alt="${escapeHtml(name)}" style="width:100%;height:100%;object-fit:cover;object-position:center top;display:block"></div>`
      : '<div class="sticker-photo fallback">Sin imagen</div>';

    const flagHtml = code
      ? `<div class="sticker-flag-img" title="${escapeHtml(code)}">${flagImg ? `<img src="${flagImg}" alt="${escapeHtml(code)}" loading="lazy" onerror="this.style.display='none';if(this.nextElementSibling)this.nextElementSibling.style.display='flex'">` : ''}<span style="display:${flagImg ? 'none' : 'flex'}">${escapeHtml(flag || code)}</span></div>`
      : '';

    const statsHtml = '<div class="sticker-stats-bar"><span class="ssb-w">12V</span><span class="ssb-l">1D</span><span class="ssb-r">★88</span></div>';

    previewWrap.innerHTML = `
      <div class="sticker-frame" style="transform:rotate(1deg)">
        <div class="sticker-card rarity-${escapeHtml(rarity)}" data-series="BLT">
          <div class="sticker-rarity"></div>
          ${photo}
          ${flagHtml}
          ${statsHtml}
          <div class="flag-tag">#001</div>
          <div class="sticker-footer">
            <div class="name-pill">${escapeHtml(name)}</div>
            <div class="meta-pill">${escapeHtml(rarityLabel(rarity))} · ${escapeHtml(subtitle)}</div>
          </div>
        </div>
      </div>`;
  }

  imgInput.addEventListener('change', (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      creatorImageDataUrl = ev.target.result;
      const short = file.name.length > 22 ? file.name.slice(0, 22) + '…' : file.name;
      uploadLabel.textContent = `Imagen lista · ${short}`;
      uploadZone.classList.add('has-image');
      buildPreview();
    };
    reader.readAsDataURL(file);
  });

  [nameInput, subtitleInput, countrySelect].forEach((el) => {
    el.addEventListener('input', buildPreview);
  });

  downloadBtn.addEventListener('click', async () => {
    const card = previewWrap.querySelector('.sticker-frame');
    if (!card) return;
    const slug = (nameInput.value.trim() || 'cromo').toLowerCase().replace(/[^a-z0-9]+/g, '-');
    await downloadStickerCard(card, `cromo-${slug}.png`);
  });

  buildPreview(); // initial render
}

async function init() {
  state.missionConfig = loadMissionConfig();
  state.playerPseudo = readPseudoFromUrl() || loadStoredPseudonimo();
  state.legacyPlayerKey = readLegacyKeyFromUrl() || loadStoredLegacyKey();
  state.sessionToken = loadStoredAlbumSessionToken();
  refs.pseudoInput.value = state.playerPseudo;
  refs.keyInput.value = '';
  hydrateRouteLinks();
  bindEvents();
  await restoreAlbumSession();
  state.pendingStickers = loadPendingStickers();
  refs.pseudoInput.value = state.playerPseudo;
  updatePendingTray();
  updateHeaderSummary();
  startAlbumViewerAutoRefresh();
  startPackCountdown();
  switchScene('intro');
  renderIntroShowcaseCards();
  await loadAlbumData();
  initCreator();
}

init();
