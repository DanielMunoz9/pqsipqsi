-- =======================
-- 1. ACTUALIZAR IMÁGENES DE ESMERALDAS Y DIAMANTES
-- =======================
-- Copia la imagen de la carta base (avatar) del jugador hacia sus variantes Diamante y Esmeralda

UPDATE album.stickers e
SET image_url = p.image_url
FROM album.stickers p
WHERE e.special_type IN ('diamante', 'esmeralda')
  AND p.sticker_type = 'player'
  AND p.special_type = 'normal'
  AND p.player_pseudo = REPLACE(REPLACE(e.player_pseudo, '_ESMERALDA', ''), '_DIAMOND', '');

-- =======================
-- 2. ACTUALIZAR IMÁGENES DE ICONOS Y EXTRAS
-- =======================

UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Bandet_Icon.jpg' WHERE player_pseudo = 'BANDET_ICON';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/EMBERICON.jpg' WHERE player_pseudo = 'EMBER_ICON';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/MERUS_ICON.jpg' WHERE player_pseudo = 'MERUS_ICON';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/AKIRA_ICON.jpg' WHERE player_pseudo = 'AKIRA_ICON';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/EGO_ICON.jpg' WHERE player_pseudo = 'EGO_ICON';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/MIMUJER.png' WHERE player_pseudo = 'INVERSE BERKANSTEL_ICON';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/RED_ICON.jpg' WHERE player_pseudo = 'RED DRAIG CRIMSON_ICON';

UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/SEKIRO.jpg' WHERE player_pseudo = 'SEKIRO_EXTRA';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/BIANCA.jpg' WHERE player_pseudo = 'BIANCA_EXTRA';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/EISENGAARD.jpg' WHERE player_pseudo = 'EISENGAARD_EXTRA';

-- =======================
-- 3. INSERTAR ICONOS Y EXTRAS (SI FALTAN)
-- =======================
-- (Si ya existen, esto puede dar error de duplicado si tienes un constraint único, o puedes ignorarlo si ya los tienes)

INSERT INTO album.stickers (series, player_pseudo, division, sticker_type, variant, special_type, display_name, rarity, slot_number, image_url)
SELECT * FROM (VALUES
  ('2026', 'BANDET_ICON', 'universal', 'player', 'normal', 'iconico', 'BANDET', 'legendario', 900, 'https://valhala-album.netlify.app/STICKERS/Bandet_Icon.jpg'),
  ('2026', 'EMBER_ICON', 'universal', 'player', 'normal', 'iconico', 'EMBER', 'legendario', 901, 'https://valhala-album.netlify.app/STICKERS/EMBERICON.jpg'),
  ('2026', 'MERUS_ICON', 'universal', 'player', 'normal', 'iconico', 'MERUS', 'legendario', 902, 'https://valhala-album.netlify.app/STICKERS/MERUS_ICON.jpg'),
  ('2026', 'AKIRA_ICON', 'universal', 'player', 'normal', 'iconico', 'AKIRA', 'legendario', 903, 'https://valhala-album.netlify.app/STICKERS/AKIRA_ICON.jpg'),
  ('2026', 'EGO_ICON', 'universal', 'player', 'normal', 'iconico', 'EGO', 'legendario', 904, 'https://valhala-album.netlify.app/STICKERS/EGO_ICON.jpg'),
  ('2026', 'INVERSE BERKANSTEL_ICON', 'universal', 'player', 'normal', 'iconico', 'INVERSE BERKANSTEL', 'legendario', 905, 'https://valhala-album.netlify.app/STICKERS/MIMUJER.png'),
  ('2026', 'RED DRAIG CRIMSON_ICON', 'universal', 'player', 'normal', 'iconico', 'RED DRAIG CRIMSON', 'legendario', 906, 'https://valhala-album.netlify.app/STICKERS/RED_ICON.jpg'),
  
  ('2026', 'SEKIRO_EXTRA', 'universal', 'player', 'blackborder', 'extra', 'SEKIRO', 'blackborder', 800, 'https://valhala-album.netlify.app/STICKERS/SEKIRO.jpg'),
  ('2026', 'BIANCA_EXTRA', 'universal', 'char_1', 'blackborder', 'extra', 'BIANCA', 'blackborder', 801, 'https://valhala-album.netlify.app/STICKERS/BIANCA.jpg'),
  ('2026', 'EISENGAARD_EXTRA', 'universal', 'char_1', 'blackborder', 'extra', 'EISENGAARD', 'blackborder', 802, 'https://valhala-album.netlify.app/STICKERS/EISENGAARD.jpg')
) AS t(series, player_pseudo, division, sticker_type, variant, special_type, display_name, rarity, slot_number, image_url)
WHERE NOT EXISTS (
    SELECT 1 FROM album.stickers s WHERE s.player_pseudo = t.player_pseudo
);

-- =======================
-- 4. GENERAR LAMINAS DORADAS PARA TODOS LOS QUE FALTAN
-- =======================
-- Copia todos los jugadores normales y les crea su variante 'dorado' si no la tienen.

INSERT INTO album.stickers (series, player_pseudo, division, sticker_type, variant, special_type, display_name, rarity, slot_number, image_url)
SELECT 
    p.series, p.player_pseudo, p.division, p.sticker_type, 'dorado', p.special_type, p.display_name, 'legendario', p.slot_number + 1000, p.image_url
FROM album.stickers p
WHERE p.sticker_type = 'player' 
  AND p.variant = 'normal' 
  AND p.special_type = 'normal'
  AND NOT EXISTS (
      SELECT 1 FROM album.stickers d 
      WHERE d.player_pseudo = p.player_pseudo 
        AND d.variant = 'dorado'
        AND d.special_type = 'normal'
  );
