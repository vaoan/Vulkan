-- Identity and the actors mirror.
--
-- Clerk is the identity. Supabase verifies the Clerk session token (third-party auth), and
-- current_user_id() maps its `sub` to the person's user_profiles.id. Every policy is written in
-- terms of current_user_id(), never of the sub itself, so identity_sub stays out of client reach.
--
-- RLS is on for every table and nothing is allowed unless a policy says so.

-- ---------------------------------------------------------------------------
-- user_profiles: one row per person this body has seen.
-- ---------------------------------------------------------------------------
create table public.user_profiles (
  id uuid primary key default gen_random_uuid(),
  identity_sub text not null unique,
  created_at timestamptz not null default now()
);

comment on table public.user_profiles is
  'One row per person. identity_sub is the Clerk sub; clients never read it.';

alter table public.user_profiles enable row level security;

create function public.current_user_id() returns uuid
  language sql stable security definer
  set search_path = public
  as $$
  select id
  from public.user_profiles
  where identity_sub = nullif(auth.jwt() ->> 'sub', '')
$$;

comment on function public.current_user_id() is
  'The signed-in person''s user_profiles.id, resolved from the Clerk sub. NULL when unknown or signed out: callers must treat NULL as deny.';

revoke all on function public.current_user_id() from public;
grant execute on function public.current_user_id() to anon, authenticated, service_role;

revoke all on public.user_profiles from anon, authenticated;
-- identity_sub is absent from the select grant: a client sees its id, never its sub.
grant select (id, created_at) on public.user_profiles to authenticated;
-- A person creates their own profile on first sign-in; id and created_at take their defaults.
grant insert (identity_sub) on public.user_profiles to authenticated;

create policy "a person reads their own profile"
  on public.user_profiles for select to authenticated
  using (id = public.current_user_id());

create policy "a person creates only their own profile"
  on public.user_profiles for insert to authenticated
  with check (identity_sub = nullif(auth.jwt() ->> 'sub', ''));

-- ---------------------------------------------------------------------------
-- actors: the mirror of the person's actors in AeleOS, keyed on actor_ref.
-- Fields follow AeleOS docs/integrating.md, "The upsert". The hub never sends who owns a row;
-- the body records it at sync time, as user_id (whose token made the call) and owner_ref.
-- ---------------------------------------------------------------------------
create table public.actors (
  actor_ref uuid primary key,
  user_id uuid not null references public.user_profiles (id) on delete cascade,
  kind text not null check (kind in ('person', 'fursona')),
  -- Unique per owner in the hub, not globally: never a key here.
  handle text not null,
  display_name text,
  avatar_url text,
  visibility text not null,
  status text not null,
  owner_ref uuid,
  synced_at timestamptz not null default now(),
  -- Target of the owner reference below.
  unique (actor_ref, user_id),
  -- A person is owned by nobody; every other actor is owned by a person.
  constraint actors_owner_shape check ((kind = 'person') = (owner_ref is null)),
  -- A fursona's owner is a person row of the same user: nobody records a fursona under
  -- someone else's person, whatever RLS lets them see.
  constraint actors_owner_same_user foreign key (owner_ref, user_id)
    references public.actors (actor_ref, user_id) on delete cascade
);

comment on table public.actors is
  'Mirror of the person''s AeleOS actors, upserted on actor_ref. The hub wins on its fields.';

create index actors_user_id_idx on public.actors (user_id);

alter table public.actors enable row level security;

revoke all on public.actors from anon, authenticated;
grant select, insert, update, delete on public.actors to authenticated;

create policy "a person reads their own actors"
  on public.actors for select to authenticated
  using (user_id = public.current_user_id());

create policy "a person records actors only for themselves"
  on public.actors for insert to authenticated
  with check (user_id = public.current_user_id());

create policy "a person updates only their own actors, and keeps them"
  on public.actors for update to authenticated
  using (user_id = public.current_user_id())
  with check (user_id = public.current_user_id());

create policy "a person removes only their own actors"
  on public.actors for delete to authenticated
  using (user_id = public.current_user_id());
