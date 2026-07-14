-- =======================
-- CORRECCION DE IMAGENES EXACTA POR SLOT NUMBER
-- =======================
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/khamzatt.webp' WHERE player_pseudo = 'Khamzat 𝕿𝖍𝖊 𝕭𝖔𝖗𝖟 𝕽𝖊𝖆𝖕𝖕𝖊𝖗' AND sticker_type = 'player';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Rune King Thor.jpg' WHERE player_pseudo = 'Khamzat 𝕿𝖍𝖊 𝕭𝖔𝖗𝖟 𝕽𝖊𝖆𝖕𝖕𝖊𝖗' AND slot_number = 11;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Michaelkorvac.webp' WHERE player_pseudo = 'Khamzat 𝕿𝖍𝖊 𝕭𝖔𝖗𝖟 𝕽𝖊𝖆𝖕𝖕𝖊𝖗' AND slot_number = 12;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Mercurius.webp' WHERE player_pseudo = 'Khamzat 𝕿𝖍𝖊 𝕭𝖔𝖗𝖟 𝕽𝖊𝖆𝖕𝖕𝖊𝖗' AND slot_number = 13;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Frisk(Undertale).jpg' WHERE player_pseudo = 'Mel' AND slot_number = 22;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Illyasviel von Einzbern(Fate Kaleid).webp' WHERE player_pseudo = 'Mel' AND slot_number = 21;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Berkanstel.webp' WHERE player_pseudo = 'Inverse Bernkastel' AND slot_number = 41;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/slurr.jpg' WHERE player_pseudo = '𝕭andet' AND sticker_type = 'player';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Doctor_Strange.webp' WHERE player_pseudo = '𝕭andet' AND slot_number = 71;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Thanoss.jpg' WHERE player_pseudo = '𝕭andet' AND slot_number = 72;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Jean gray.webp' WHERE player_pseudo = '𝕭andet' AND slot_number = 73;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Zarathos (Ghost Rider).jpg' WHERE player_pseudo = 'Lucifer Der Vosgrönne' AND slot_number = 92;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Elric de Melniboné.jpg' WHERE player_pseudo = 'Lucifer Der Vosgrönne' AND slot_number = 93;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Beatrice The Golden Wich.jpg' WHERE player_pseudo = 'RagnaKurenai' AND slot_number = 131;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Kojou Akatsuki.jpeg' WHERE player_pseudo = 'RagnaKurenai' AND slot_number = 133;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Dktosh.jpg' WHERE player_pseudo = 'Dktosh Dmitriev' AND sticker_type = 'player';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/永. 𝐇𝐚𝐭𝐬𝐮𝐦𝐢.jpeg' WHERE player_pseudo = '永. 𝐇𝐚𝐭𝐬𝐮𝐦𝐢' AND sticker_type = 'player';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/𝕽𝐲𝐮𝐮..jpg' WHERE player_pseudo = '𝕽𝐲𝐮𝐮.' AND sticker_type = 'player';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Madara Uchiha..jpg' WHERE player_pseudo = '𝕽𝐲𝐮𝐮.' AND slot_number = 282;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/Yatogami tenka – date a live.webp' WHERE player_pseudo = 'тєηкα' AND slot_number = 303;
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/EISENGAARD.jpg' WHERE player_pseudo = 'EISENGAARD' AND sticker_type = 'player';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/EISENGAARD.jpg' WHERE display_name = 'EISENGAARD' AND special_type = 'extra';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/BIANCA.jpg' WHERE player_pseudo = 'BIANCA' AND sticker_type = 'player';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/BIANCA.jpg' WHERE display_name = 'BIANCA' AND special_type = 'extra';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/SEKIRO.jpg' WHERE player_pseudo = 'SEKIRO' AND sticker_type = 'player';
UPDATE album.stickers SET image_url = 'https://valhala-album.netlify.app/STICKERS/SEKIRO.jpg' WHERE display_name = 'SEKIRO' AND special_type = 'extra';

-- =======================
-- ACTUALIZAR CONSTRAINTS PARA ESMERALDA
-- =======================
ALTER TABLE album.stickers DROP CONSTRAINT IF EXISTS stickers_special_type_check;
ALTER TABLE album.stickers ADD CONSTRAINT stickers_special_type_check CHECK (special_type IN ('normal', 'iconico', 'extra', 'diamante', 'esmeralda'));

-- =======================
-- NUEVAS ESMERALDAS (37 cartas)
-- =======================
INSERT INTO album.stickers (series, player_pseudo, division, sticker_type, variant, special_type, display_name, rarity, slot_number, max_copies)
VALUES
  ('2026', 'ARAKIEL_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'ARAKIEL', 'legendario', 3000, 1),
  ('2026', 'Abssylum_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Abssylum', 'legendario', 3001, 1),
  ('2026', 'Amiya Arknights_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Amiya Arknights', 'legendario', 3002, 1),
  ('2026', 'Dhaela_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Dhaela', 'legendario', 3003, 1),
  ('2026', 'Dktosh Dmitriev_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Dktosh Dmitriev', 'legendario', 3004, 1),
  ('2026', 'Fear._ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Fear.', 'legendario', 3005, 1),
  ('2026', 'GULTARD GABANNA_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'GULTARD GABANNA', 'legendario', 3006, 1),
  ('2026', 'Heather Yack_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Heather Yack', 'legendario', 3007, 1),
  ('2026', 'Inverse Bernkastel_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Inverse Bernkastel', 'legendario', 3008, 1),
  ('2026', 'Justice63_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Justice63', 'legendario', 3009, 1),
  ('2026', 'Khamzat 𝕿𝖍𝖊 𝕭𝖔𝖗𝖟 𝕽𝖊𝖆𝖕𝖕𝖊𝖗_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Khamzat 𝕿𝖍𝖊 𝕭𝖔𝖗𝖟 𝕽𝖊𝖆𝖕𝖕𝖊𝖗', 'legendario', 3010, 1),
  ('2026', 'Lucifer Der Vosgrönne_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Lucifer Der Vosgrönne', 'legendario', 3011, 1),
  ('2026', 'Mel_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Mel', 'legendario', 3012, 1),
  ('2026', 'Musashi_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Musashi', 'legendario', 3013, 1),
  ('2026', 'NeroAggelo_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'NeroAggelo', 'legendario', 3014, 1),
  ('2026', 'Ohma_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Ohma', 'legendario', 3015, 1),
  ('2026', 'Prox_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Prox', 'legendario', 3016, 1),
  ('2026', 'RagnaKurenai_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'RagnaKurenai', 'legendario', 3017, 1),
  ('2026', 'Sak_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Sak', 'legendario', 3018, 1),
  ('2026', 'Soujiro Izanagi_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Soujiro Izanagi', 'legendario', 3019, 1),
  ('2026', 'Thunder     ¡_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Thunder     ¡', 'legendario', 3020, 1),
  ('2026', 'Vertic_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'Vertic', 'legendario', 3021, 1),
  ('2026', 'тєηкα_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'тєηкα', 'legendario', 3022, 1),
  ('2026', '永. 𝐇𝐚𝐭𝐬𝐮𝐦𝐢_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', '永. 𝐇𝐚𝐭𝐬𝐮𝐦𝐢', 'legendario', 3023, 1),
  ('2026', '𝐉𝐈𝐌 𝕸𝖊𝖗𝖚𝖘 𝕵𝖗._ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', '𝐉𝐈𝐌 𝕸𝖊𝖗𝖚𝖘 𝕵𝖗.', 'legendario', 3024, 1),
  ('2026', '𝐍𝐄𝐏𝐇𝐀𝐋𝐄𝐌_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', '𝐍𝐄𝐏𝐇𝐀𝐋𝐄𝐌', 'legendario', 3025, 1),
  ('2026', '𝕭andet_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', '𝕭andet', 'legendario', 3026, 1),
  ('2026', '𝕭𝐚𝐚𝐥_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', '𝕭𝐚𝐚𝐥', 'legendario', 3027, 1),
  ('2026', '𝕽𝐲𝐮𝐮._ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', '𝕽𝐲𝐮𝐮.', 'legendario', 3028, 1),
  ('2026', '𝗠𝐄𝐑𝐔𝐒_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', '𝗠𝐄𝐑𝐔𝐒', 'legendario', 3029, 1),
  ('2026', 'BANDET_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'BANDET', 'legendario', 3030, 1),
  ('2026', 'EMBER_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'EMBER', 'legendario', 3031, 1),
  ('2026', 'MERUS_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'MERUS', 'legendario', 3032, 1),
  ('2026', 'AKIRA_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'AKIRA', 'legendario', 3033, 1),
  ('2026', 'EGO_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'EGO', 'legendario', 3034, 1),
  ('2026', 'INVERSE BERKANSTEL_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'INVERSE BERKANSTEL', 'legendario', 3035, 1),
  ('2026', 'RED DRAIG CRIMSON_ESMERALDA', 'universal', 'player', 'dorado', 'esmeralda', 'RED DRAIG CRIMSON', 'legendario', 3036, 1);