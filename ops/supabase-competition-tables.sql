begin;

create table if not exists public.match_history (
    id bigserial primary key,
    created_at timestamptz not null default now(),
    event_name text not null default 'Torneo Bellator 2026',
    event_date date not null default current_date,
    player1_pseudo text not null,
    player2_pseudo text not null,
    player1_avatar text,
    player2_avatar text,
    result text not null,
    player1_char text,
    player2_char text,
    division text,
    notes text,
    constraint match_history_result_check check (result in ('player1', 'player2', 'draw'))
);

alter table public.match_history add column if not exists created_at timestamptz not null default now();
alter table public.match_history add column if not exists event_name text not null default 'Torneo Bellator 2026';
alter table public.match_history add column if not exists event_date date not null default current_date;
alter table public.match_history add column if not exists player1_pseudo text not null default '';
alter table public.match_history add column if not exists player2_pseudo text not null default '';
alter table public.match_history add column if not exists player1_avatar text;
alter table public.match_history add column if not exists player2_avatar text;
alter table public.match_history add column if not exists result text not null default 'draw';
alter table public.match_history add column if not exists player1_char text;
alter table public.match_history add column if not exists player2_char text;
alter table public.match_history add column if not exists division text;
alter table public.match_history add column if not exists notes text;

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'match_history_result_check'
          and conrelid = 'public.match_history'::regclass
    ) then
        alter table public.match_history
            add constraint match_history_result_check check (result in ('player1', 'player2', 'draw'));
    end if;
end $$;

create index if not exists match_history_event_date_idx on public.match_history (event_date desc);
create index if not exists match_history_player1_pseudo_idx on public.match_history (lower(player1_pseudo));
create index if not exists match_history_player2_pseudo_idx on public.match_history (lower(player2_pseudo));

create table if not exists public.upcoming_fights (
    id bigserial primary key,
    created_at timestamptz not null default now(),
    player1_pseudo text not null,
    player2_pseudo text not null,
    player1_avatar text,
    player2_avatar text,
    event_date date not null,
    event_name text not null default 'Bellator RolBattle',
    division text,
    notes text
);

alter table public.upcoming_fights add column if not exists created_at timestamptz not null default now();
alter table public.upcoming_fights add column if not exists player1_pseudo text not null default '';
alter table public.upcoming_fights add column if not exists player2_pseudo text not null default '';
alter table public.upcoming_fights add column if not exists player1_avatar text;
alter table public.upcoming_fights add column if not exists player2_avatar text;
alter table public.upcoming_fights add column if not exists event_date date not null default current_date;
alter table public.upcoming_fights add column if not exists event_name text not null default 'Bellator RolBattle';
alter table public.upcoming_fights add column if not exists division text;
alter table public.upcoming_fights add column if not exists notes text;

create index if not exists upcoming_fights_event_date_idx on public.upcoming_fights (event_date asc);
create index if not exists upcoming_fights_player1_pseudo_idx on public.upcoming_fights (lower(player1_pseudo));
create index if not exists upcoming_fights_player2_pseudo_idx on public.upcoming_fights (lower(player2_pseudo));

grant all on table public.match_history to service_role;
grant usage, select on sequence public.match_history_id_seq to service_role;
grant all on table public.upcoming_fights to service_role;
grant usage, select on sequence public.upcoming_fights_id_seq to service_role;

notify pgrst, 'reload schema';

commit;