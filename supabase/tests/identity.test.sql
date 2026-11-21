-- Identity and the actors mirror: who current_user_id() says you are, and what RLS lets you touch.
-- Person A and person B are impersonated through request.jwt.claims, the way PostgREST passes a
-- verified Clerk token; everything runs in one transaction and is rolled back.
begin;

select plan(24);

-- Fixtures, written as the owner (RLS does not apply).
insert into public.user_profiles (id, identity_sub) values
  ('00000000-0000-4000-8000-00000000000a', 'user_a'),
  ('00000000-0000-4000-8000-00000000000b', 'user_b');

insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref) values
  ('10000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a', 'person', 'u-a', 'private', 'active', null),
  ('20000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a', 'fursona', 'luna', 'public', 'active', '10000000-0000-4000-8000-00000000000a'),
  ('10000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-00000000000b', 'person', 'u-b', 'private', 'active', null),
  ('20000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-00000000000b', 'fursona', 'luna', 'public', 'active', '10000000-0000-4000-8000-00000000000b');

-- Every table in public has RLS on.
select is(
  (select count(*)::int from pg_class
    where relnamespace = 'public'::regnamespace and relkind = 'r' and not relrowsecurity),
  0,
  'every table in public has row level security enabled'
);

select function_returns('public', 'current_user_id', array[]::text[], 'uuid', 'current_user_id() returns uuid');

select is(
  (select prosecdef from pg_proc where oid = 'public.current_user_id()'::regprocedure),
  true,
  'current_user_id() is security definer'
);

-- No JWT.
set local role anon;
select set_config('request.jwt.claims', '', true);

select is(public.current_user_id(), null, 'with no JWT, current_user_id() is null');

select throws_ok(
  'select count(*) from public.actors',
  '42501',
  null,
  'with no JWT, actors cannot be read at all'
);

-- Person A.
reset role;
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;

select is(
  public.current_user_id(),
  '00000000-0000-4000-8000-00000000000a'::uuid,
  'with the sub of A, current_user_id() is A''s profile id'
);

select is(
  (select count(*)::int from public.user_profiles),
  1,
  'A sees exactly one profile'
);

select is(
  (select id from public.user_profiles),
  '00000000-0000-4000-8000-00000000000a'::uuid,
  'the one profile A sees is A''s own'
);

select throws_ok(
  'select identity_sub from public.user_profiles',
  '42501',
  null,
  'identity_sub is not readable by a client'
);

select is(
  (select count(*)::int from public.actors),
  2,
  'A sees only A''s two actors'
);

select is(
  (select count(*)::int from public.actors where user_id = '00000000-0000-4000-8000-00000000000b'),
  0,
  'A cannot select B''s actors'
);

select throws_ok(
  $$insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref)
    values ('30000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-00000000000b',
            'fursona', 'stolen', 'public', 'active', '10000000-0000-4000-8000-00000000000b')
    on conflict (actor_ref) do update set handle = excluded.handle$$,
  '42501',
  null,
  'an actor upsert by A for B''s user_id is refused'
);

select throws_ok(
  $$insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref)
    values ('20000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-00000000000a',
            'fursona', 'taken', 'public', 'active', '10000000-0000-4000-8000-00000000000a')
    on conflict (actor_ref) do update set handle = excluded.handle, user_id = excluded.user_id$$,
  '42501',
  null,
  'an upsert by A onto B''s existing actor_ref is refused'
);

select throws_ok(
  $$update public.actors set user_id = '00000000-0000-4000-8000-00000000000b'
    where actor_ref = '20000000-0000-4000-8000-00000000000a'$$,
  '42501',
  null,
  'A cannot hand one of A''s actors to B'
);

select lives_ok(
  $$insert into public.actors (actor_ref, user_id, kind, handle, display_name, visibility, status, owner_ref)
    values ('20000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a',
            'fursona', 'luna', 'Luna', 'public', 'suspended', '10000000-0000-4000-8000-00000000000a')
    on conflict (actor_ref) do update set display_name = excluded.display_name, status = excluded.status,
      synced_at = now()$$,
  'A can upsert A''s own actor, keyed on actor_ref'
);

select throws_ok(
  $$insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref)
    values ('40000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a',
            'fursona', 'borrowed', 'public', 'active', '10000000-0000-4000-8000-00000000000b')$$,
  '23503',
  null,
  'A cannot record a fursona as owned by B''s person'
);

select throws_ok(
  $$insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref)
    values ('50000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a',
            'fursona', 'orphan', 'public', 'active', null)$$,
  '23514',
  null,
  'a fursona must have an owner, and only a person may have none'
);

select throws_ok(
  $$insert into public.user_profiles (identity_sub) values ('user_c')$$,
  '42501',
  null,
  'A cannot create a profile for another sub'
);

-- Person B, to see what A's attempts left behind.
reset role;
select set_config('request.jwt.claims', '{"sub":"user_b","role":"authenticated"}', true);
set local role authenticated;

select is(
  public.current_user_id(),
  '00000000-0000-4000-8000-00000000000b'::uuid,
  'with the sub of B, current_user_id() is B''s profile id'
);

select is(
  (select handle from public.actors where actor_ref = '20000000-0000-4000-8000-00000000000b'),
  'luna',
  'B''s fursona is untouched, and shares its handle with A''s'
);

-- A token whose sub has no profile yet.
reset role;
select set_config('request.jwt.claims', '{"sub":"user_unknown","role":"authenticated"}', true);
set local role authenticated;

select is(public.current_user_id(), null, 'a sub with no profile resolves to null');

select lives_ok(
  $$insert into public.user_profiles (identity_sub) values ('user_unknown')$$,
  'a person can create their own profile, on first sign-in'
);

select isnt(public.current_user_id(), null, 'once created, the profile is who current_user_id() says they are');

select is(
  (select count(*)::int from public.actors),
  0,
  'a new person sees no one else''s actors'
);

select * from finish();
rollback;
