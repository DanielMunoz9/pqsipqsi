-- 1. Actualizar constraints (special_type, variant, rarity)
ALTER TABLE album.stickers DROP CONSTRAINT IF EXISTS stickers_special_type_check;
ALTER TABLE album.stickers ADD CONSTRAINT stickers_special_type_check CHECK (special_type IN ('normal', 'iconico', 'extra', 'diamante'));

ALTER TABLE album.stickers DROP CONSTRAINT IF EXISTS stickers_variant_check;
ALTER TABLE album.stickers ADD CONSTRAINT stickers_variant_check CHECK (variant IN ('normal', 'dorado', 'blackborder', 'epico'));

ALTER TABLE album.stickers DROP CONSTRAINT IF EXISTS stickers_rarity_check;
ALTER TABLE album.stickers ADD CONSTRAINT stickers_rarity_check CHECK (rarity IN ('comun', 'raro', 'epico', 'legendario', 'blackborder'));

-- 2. Insertar Icónicos
INSERT INTO album.stickers (series, player_pseudo, division, sticker_type, variant, special_type, display_name, rarity, slot_number, max_copies)
VALUES
  ('2026', 'BANDET_ICON', 'universal', 'player', 'normal', 'iconico', 'BANDET', 'legendario', 900, NULL),
  ('2026', 'EMBER_ICON', 'universal', 'player', 'normal', 'iconico', 'EMBER', 'legendario', 901, NULL),
  ('2026', 'MERUS_ICON', 'universal', 'player', 'normal', 'iconico', 'MERUS', 'legendario', 902, NULL),
  ('2026', 'AKIRA_ICON', 'universal', 'player', 'normal', 'iconico', 'AKIRA', 'legendario', 903, NULL),
  ('2026', 'EGO_ICON', 'universal', 'player', 'normal', 'iconico', 'EGO', 'legendario', 904, NULL),
  ('2026', 'INVERSE BERKANSTEL_ICON', 'universal', 'player', 'normal', 'iconico', 'INVERSE BERKANSTEL', 'legendario', 905, NULL),
  ('2026', 'RED DRAIG CRIMSON_ICON', 'universal', 'player', 'normal', 'iconico', 'RED DRAIG CRIMSON', 'legendario', 906, NULL);

-- 3. Insertar Extras (Black Border)
INSERT INTO album.stickers (series, player_pseudo, division, sticker_type, variant, special_type, display_name, rarity, slot_number, max_copies)
VALUES
  ('2026', 'SEKIRO_EXTRA', 'universal', 'player', 'blackborder', 'extra', 'SEKIRO', 'blackborder', 800, NULL),
  ('2026', 'BIANCA_EXTRA', 'universal', 'char_1', 'blackborder', 'extra', 'BIANCA', 'blackborder', 801, NULL),
  ('2026', 'EISENGAARD_EXTRA', 'universal', 'char_1', 'blackborder', 'extra', 'EISENGAARD', 'blackborder', 802, NULL);

-- 4. Insertar Diamantes (Uno por jugador del roster)
INSERT INTO album.stickers (series, player_pseudo, division, sticker_type, variant, special_type, display_name, rarity, slot_number, max_copies)
VALUES
  ('2026', 'ARAKIEL_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'ARAKIEL', 'legendario', 2000, 1),
  ('2026', 'Abssylum_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Abssylum', 'legendario', 2001, 1),
  ('2026', 'Amiya Arknights_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Amiya Arknights', 'legendario', 2002, 1),
  ('2026', 'Dhaela_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Dhaela', 'legendario', 2003, 1),
  ('2026', 'Dktosh Dmitriev_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Dktosh Dmitriev', 'legendario', 2004, 1),
  ('2026', 'Fear._DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Fear.', 'legendario', 2005, 1),
  ('2026', 'GULTARD GABANNA_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'GULTARD GABANNA', 'legendario', 2006, 1),
  ('2026', 'Heather Yack_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Heather Yack', 'legendario', 2007, 1),
  ('2026', 'Inverse Bernkastel_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Inverse Bernkastel', 'legendario', 2008, 1),
  ('2026', 'Justice63_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Justice63', 'legendario', 2009, 1),
  ('2026', 'Khamzat 𝕿𝖍𝖊 𝕭𝖔𝖗𝖟 𝕽𝖊𝖆𝖕𝖕𝖊𝖗_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Khamzat 𝕿𝖍𝖊 𝕭𝖔𝖗𝖟 𝕽𝖊𝖆𝖕𝖕𝖊𝖗', 'legendario', 2010, 1),
  ('2026', 'Lucifer Der Vosgrönne_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Lucifer Der Vosgrönne', 'legendario', 2011, 1),
  ('2026', 'Mel_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Mel', 'legendario', 2012, 1),
  ('2026', 'Musashi_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Musashi', 'legendario', 2013, 1),
  ('2026', 'NeroAggelo_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'NeroAggelo', 'legendario', 2014, 1),
  ('2026', 'Ohma_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Ohma', 'legendario', 2015, 1),
  ('2026', 'Prox_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Prox', 'legendario', 2016, 1),
  ('2026', 'RagnaKurenai_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'RagnaKurenai', 'legendario', 2017, 1),
  ('2026', 'Sak_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Sak', 'legendario', 2018, 1),
  ('2026', 'Soujiro Izanagi_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Soujiro Izanagi', 'legendario', 2019, 1),
  ('2026', 'Thunder     ¡_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Thunder     ¡', 'legendario', 2020, 1),
  ('2026', 'Vertic_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'Vertic', 'legendario', 2021, 1),
  ('2026', 'тєηкα_DIAMOND', 'universal', 'player', 'dorado', 'diamante', 'тєηкα', 'legendario', 2022, 1),
  ('2026', '永. 𝐇𝐚𝐭𝐬𝐮𝐦𝐢_DIAMOND', 'universal', 'player', 'dorado', 'diamante', '永. 𝐇𝐚𝐭𝐬𝐮𝐦𝐢', 'legendario', 2023, 1),
  ('2026', '𝐉𝐈𝐌 𝕸𝖊𝖗𝖚𝖘 𝕵𝖗._DIAMOND', 'universal', 'player', 'dorado', 'diamante', '𝐉𝐈𝐌 𝕸𝖊𝖗𝖚𝖘 𝕵𝖗.', 'legendario', 2024, 1),
  ('2026', '𝐍𝐄𝐏𝐇𝐀𝐋𝐄𝐌_DIAMOND', 'universal', 'player', 'dorado', 'diamante', '𝐍𝐄𝐏𝐇𝐀𝐋𝐄𝐌', 'legendario', 2025, 1),
  ('2026', '𝕭andet_DIAMOND', 'universal', 'player', 'dorado', 'diamante', '𝕭andet', 'legendario', 2026, 1),
  ('2026', '𝕭𝐚𝐚𝐥_DIAMOND', 'universal', 'player', 'dorado', 'diamante', '𝕭𝐚𝐚𝐥', 'legendario', 2027, 1),
  ('2026', '𝕽𝐲𝐮𝐮._DIAMOND', 'universal', 'player', 'dorado', 'diamante', '𝕽𝐲𝐮𝐮.', 'legendario', 2028, 1),
  ('2026', '𝗠𝐄𝐑𝐔𝐒_DIAMOND', 'universal', 'player', 'dorado', 'diamante', '𝗠𝐄𝐑𝐔𝐒', 'legendario', 2029, 1);

-- 5. Insertar Épicos (Una variante épica especial por cada jugador activo)
INSERT INTO album.stickers (series, player_pseudo, division, sticker_type, variant, special_type, display_name, rarity, slot_number, max_copies)
VALUES
  ('2026', 'ARAKIEL', 'universal', 'player', 'epico', 'normal', 'ARAKIEL', 'epico', 500, NULL),
  ('2026', 'Abssylum', 'universal', 'player', 'epico', 'normal', 'Abssylum', 'epico', 501, NULL),
  ('2026', 'Amiya Arknights', 'universal', 'player', 'epico', 'normal', 'Amiya Arknights', 'epico', 502, NULL),
  ('2026', 'Dhaela', 'universal', 'player', 'epico', 'normal', 'Dhaela', 'epico', 503, NULL),
  ('2026', 'Dktosh Dmitriev', 'universal', 'player', 'epico', 'normal', 'Dktosh Dmitriev', 'epico', 504, NULL),
  ('2026', 'Fear.', 'universal', 'player', 'epico', 'normal', 'Fear.', 'epico', 505, NULL),
  ('2026', 'GULTARD GABANNA', 'universal', 'player', 'epico', 'normal', 'GULTARD GABANNA', 'epico', 506, NULL),
  ('2026', 'Heather Yack', 'universal', 'player', 'epico', 'normal', 'Heather Yack', 'epico', 507, NULL),
  ('2026', 'Inverse Bernkastel', 'universal', 'player', 'epico', 'normal', 'Inverse Bernkastel', 'epico', 508, NULL),
  ('2026', 'Justice63', 'universal', 'player', 'epico', 'normal', 'Justice63', 'epico', 509, NULL),
  ('2026', 'Khamzat 𝕿𝖍𝖊 𝕭𝖔𝖗𝖟 𝕽𝖊𝖆𝖕𝖕𝖊𝖗', 'universal', 'player', 'epico', 'normal', 'Khamzat 𝕿𝖍𝖊 𝕭𝖔𝖗𝖟 𝕽𝖊𝖆𝖕𝖕𝖊𝖗', 'epico', 510, NULL),
  ('2026', 'Lucifer Der Vosgrönne', 'universal', 'player', 'epico', 'normal', 'Lucifer Der Vosgrönne', 'epico', 511, NULL),
  ('2026', 'Mel', 'universal', 'player', 'epico', 'normal', 'Mel', 'epico', 512, NULL),
  ('2026', 'Musashi', 'universal', 'player', 'epico', 'normal', 'Musashi', 'epico', 513, NULL),
  ('2026', 'NeroAggelo', 'universal', 'player', 'epico', 'normal', 'NeroAggelo', 'epico', 514, NULL),
  ('2026', 'Ohma', 'universal', 'player', 'epico', 'normal', 'Ohma', 'epico', 515, NULL),
  ('2026', 'Prox', 'universal', 'player', 'epico', 'normal', 'Prox', 'epico', 516, NULL),
  ('2026', 'RagnaKurenai', 'universal', 'player', 'epico', 'normal', 'RagnaKurenai', 'epico', 517, NULL),
  ('2026', 'Sak', 'universal', 'player', 'epico', 'normal', 'Sak', 'epico', 518, NULL),
  ('2026', 'Soujiro Izanagi', 'universal', 'player', 'epico', 'normal', 'Soujiro Izanagi', 'epico', 519, NULL),
  ('2026', 'Thunder     ¡', 'universal', 'player', 'epico', 'normal', 'Thunder     ¡', 'epico', 520, NULL),
  ('2026', 'Vertic', 'universal', 'player', 'epico', 'normal', 'Vertic', 'epico', 521, NULL),
  ('2026', 'тєηкα', 'universal', 'player', 'epico', 'normal', 'тєηкα', 'epico', 522, NULL),
  ('2026', '永. 𝐇𝐚𝐭𝐬𝐮𝐦𝐢', 'universal', 'player', 'epico', 'normal', '永. 𝐇𝐚𝐭𝐬𝐮𝐦𝐢', 'epico', 523, NULL),
  ('2026', '𝐉𝐈𝐌 𝕸𝖊𝖗𝖚𝖘 𝕵𝖗.', 'universal', 'player', 'epico', 'normal', '𝐉𝐈𝐌 𝕸𝖊𝖗𝖚𝖘 𝕵𝖗.', 'epico', 524, NULL),
  ('2026', '𝐍𝐄𝐏𝐇𝐀𝐋𝐄𝐌', 'universal', 'player', 'epico', 'normal', '𝐍𝐄𝐏𝐇𝐀𝐋𝐄𝐌', 'epico', 525, NULL),
  ('2026', '𝕭andet', 'universal', 'player', 'epico', 'normal', '𝕭andet', 'epico', 526, NULL),
  ('2026', '𝕭𝐚𝐚𝐥', 'universal', 'player', 'epico', 'normal', '𝕭𝐚𝐚𝐥', 'epico', 527, NULL),
  ('2026', '𝕽𝐲𝐮𝐮.', 'universal', 'player', 'epico', 'normal', '𝕽𝐲𝐮𝐮.', 'epico', 528, NULL),
  ('2026', '𝗠𝐄𝐑𝐔𝐒', 'universal', 'player', 'epico', 'normal', '𝗠𝐄𝐑𝐔𝐒', 'epico', 529, NULL);

-- 6. Resolver duplicados y conflictos (Opcional si es necesario en caso de inserciones repetidas, pero usamos on conflict update en el script JS)