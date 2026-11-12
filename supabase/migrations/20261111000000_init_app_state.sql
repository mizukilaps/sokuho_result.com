create table if not exists public.app_state (
  id integer primary key check (id = 1),
  version bigint not null default 0,
  state jsonb not null
);

alter table public.app_state enable row level security;
revoke all on public.app_state from anon, authenticated;
grant all on public.app_state to service_role;

insert into public.app_state (id, version, state)
values (
  1,
  0,
  '{"races": {}, "accounts": {"users": [], "sessions": {}}}'::jsonb
)
on conflict (id) do nothing;
