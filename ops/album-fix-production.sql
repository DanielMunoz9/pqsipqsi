-- ══════════════════════════════════════════════════════════════════════
-- FIX PRODUCCIÓN — Álbum Bellator deja de ser "demo"
-- Ejecutar UNA vez en: Supabase Dashboard → SQL Editor → New query → Run
-- ══════════════════════════════════════════════════════════════════════
-- Qué arregla:
--   1. Expone el esquema `album` a la API REST (PostgREST) → sin esto el
--      backend recibe PGRST106 "Invalid schema: album" y el catálogo cae a demo.
--   2. Garantiza que existan las tablas del álbum (idempotente).
--   3. Cambia user_stickers/pack_openings.user_id de uuid(auth.users) a text,
--      porque las sesiones del álbum usan hardware_fingerprint / "pseudo:<nombre>"
--      (texto), no uuid de auth.users → si no, abrir sobres falla.
-- ══════════════════════════════════════════════════════════════════════

begin;

-- ── 1. Esquema + tablas (idempotente) ────────────────────────────────
create schema if not exists album;

create table if not exists album.stickers (
    id              uuid        primary key default gen_random_uuid(),
    series          text        not null default '2026',
    player_pseudo   text        not null,
    division        text        not null default 'universal'
                                check (division in ('universal', 'ciudad')),
    sticker_type    text        not null
                                check (sticker_type in ('player', 'char_1', 'char_2', 'char_3')),
    variant         text        not null default 'normal'
                                check (variant in ('normal', 'dorado')),
    display_name    text        not null,
    image_url       text,
    rarity          text        not null default 'comun'
                                check (rarity in ('comun', 'raro', 'epico', 'legendario')),
    slot_number     int         not null,
    max_copies      int,
    created_at      timestamptz not null default now(),
    unique (player_pseudo, sticker_type, variant, series)
);

create table if not exists album.user_stickers (
    id              uuid        primary key default gen_random_uuid(),
    user_id         text        not null,
    sticker_id      uuid        not null references album.stickers(id) on delete cascade,
    quantity        int         not null default 1 check (quantity >= 1),
    obtained_at     timestamptz not null default now(),
    unique (user_id, sticker_id)
);

create table if not exists album.pack_openings (
    id              uuid        primary key default gen_random_uuid(),
    user_id         text        not null,
    pack_type       text        not null default 'standard',
    stickers_json   jsonb       not null,
    opened_at       timestamptz not null default now()
);

create table if not exists album.app_config (
  id              uuid        primary key default gen_random_uuid(),
  config_key      text        not null unique,
  config_value    text        not null,
  updated_at      timestamptz not null default now(),
  created_at      timestamptz not null default now()
);

create table if not exists album.user_pack_balances (
  id              uuid        primary key default gen_random_uuid(),
  user_id         text        not null unique,
  bonus_packs     int         not null default 0 check (bonus_packs >= 0),
  updated_at      timestamptz not null default now(),
  created_at      timestamptz not null default now()
);

create index if not exists idx_stickers_player    on album.stickers (player_pseudo);
create index if not exists idx_stickers_division  on album.stickers (division);
create index if not exists idx_stickers_rarity    on album.stickers (rarity, variant);
create index if not exists idx_user_stickers_user on album.user_stickers (user_id);
create index if not exists idx_pack_openings_user on album.pack_openings (user_id);
create index if not exists idx_user_pack_balances_user on album.user_pack_balances (user_id);

-- ── 2.0. Limpiar vistas heredadas que dependen de user_id ───────────
-- Algunas bases viejas montaron vistas auxiliares sobre user_stickers y
-- pack_openings usando user_id::uuid. Esas vistas también bloquean el
-- ALTER COLUMN. No son requeridas por el backend actual, así que se
-- eliminan si existen antes de migrar el tipo.
do $$
declare
  view_row record;
begin
  for view_row in
    select distinct view_schema, view_name
    from information_schema.view_table_usage
    where view_schema = 'album'
      and table_schema = 'album'
      and table_name in ('user_stickers', 'pack_openings')
  loop
    execute format(
      'drop view if exists %I.%I',
      view_row.view_schema,
      view_row.view_name
    );
  end loop;
end $$;

-- ── 2.a. Limpiar políticas heredadas que referencian user_id ─────────
-- Algunas instalaciones viejas del álbum crearon políticas RLS sobre
-- user_stickers/pack_openings comparando auth.uid() con user_id::uuid.
-- Esas políticas bloquean el ALTER COLUMN aunque el backend actual use
-- service_role y no dependa de RLS para estas tablas. Para evitar quedar
-- atados a nombres históricos concretos, se eliminan todas las políticas
-- existentes en ambas tablas antes de migrar el tipo.
do $$
declare
  policy_row record;
begin
  for policy_row in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'album'
      and tablename in ('user_stickers', 'pack_openings')
  loop
    execute format(
      'drop policy if exists %I on %I.%I',
      policy_row.policyname,
      policy_row.schemaname,
      policy_row.tablename
    );
  end loop;
end $$;

-- ── 2. Migrar columnas user_id a TEXT (si vienen de una versión vieja) ─
do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'album' and table_name = 'user_stickers'
      and column_name = 'user_id' and data_type = 'uuid'
  ) then
    alter table album.user_stickers drop constraint if exists user_stickers_user_id_fkey;
    alter table album.user_stickers alter column user_id type text using user_id::text;
  end if;

  if exists (
    select 1 from information_schema.columns
    where table_schema = 'album' and table_name = 'pack_openings'
      and column_name = 'user_id' and data_type = 'uuid'
  ) then
    alter table album.pack_openings drop constraint if exists pack_openings_user_id_fkey;
    alter table album.pack_openings alter column user_id type text using user_id::text;
  end if;
end $$;

-- ── 3. Permisos: el backend Go y el seed usan service_role ───────────
grant usage on schema album to anon, authenticated, service_role;
grant all   on all tables    in schema album to service_role;
grant select on album.stickers to anon, authenticated;

-- RLS: el backend opera con service_role (bypassa RLS). Mantener lectura
-- pública del catálogo; el inventario lo controla el backend.
alter table album.stickers      enable row level security;
alter table album.user_stickers enable row level security;
alter table album.pack_openings enable row level security;
alter table album.app_config enable row level security;
alter table album.user_pack_balances enable row level security;

drop policy if exists "stickers_public_read" on album.stickers;
create policy "stickers_public_read" on album.stickers for select using (true);

commit;

-- ── 4. Exponer el esquema `album` a PostgREST (FUERA de la transacción) ─
alter role authenticator set pgrst.db_schemas = 'public, graphql_public, album';
notify pgrst, 'reload config';

-- Verificación rápida (debe devolver 0 o más, sin error de esquema):
-- select count(*) from album.stickers;
