-- Identity and the actors mirror: who current_user_id() says you are, and what RLS lets you touch.
-- Only the server (service_role) writes actors; a person's own token only reads them.
-- Person A and person B are impersonated through request.jwt.claims, the way PostgREST passes a
-- verified Clerk token; everything runs in one transaction and is rolled back.
begin;

select plan(30);

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

-- Controls, as the owner: both people really have actors, so a zero below is RLS, not an empty table.
select is(
  (select count(*)::int from public.actors where user_id = '00000000-0000-4000-8000-00000000000b'),
  2,
  'control: B has two actors in the mirror'
);

-- A handle is unique per owner, not globally: two people each keep a fursona called luna.
select is(
  (select count(distinct user_id)::int from public.actors where kind = 'fursona' and handle = 'luna'),
  2,
  'two users can both have a fursona with the handle luna'
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
    values ('30000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a',
            'fursona', 'mine', 'public', 'active', '10000000-0000-4000-8000-00000000000a')$$,
  '42501',
  null,
  'authenticated cannot insert an actor, even one for themselves'
);

select throws_ok(
  $$insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref)
    values ('20000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-00000000000a',
            'fursona', 'taken', 'public', 'active', '10000000-0000-4000-8000-00000000000a')
    on conflict (actor_ref) do update set user_id = excluded.user_id$$,
  '42501',
  null,
  'authenticated cannot upsert onto another person''s actor_ref'
);

select throws_ok(
  $$update public.actors set status = 'active', visibility = 'public'
    where actor_ref = '20000000-0000-4000-8000-00000000000a'$$,
  '42501',
  null,
  'authenticated cannot update actors, not even their own fursona''s status'
);

select throws_ok(
  $$delete from public.actors where actor_ref = '20000000-0000-4000-8000-00000000000a'$$,
  '42501',
  null,
  'authenticated cannot delete actors'
);

select throws_ok(
  $$insert into public.user_profiles (identity_sub) values ('user_c')$$,
  '42501',
  null,
  'A cannot create a profile for another sub'
);

-- Person B.
reset role;
select set_config('request.jwt.claims', '{"sub":"user_b","role":"authenticated"}', true);
set local role authenticated;

select is(
  public.current_user_id(),
  '00000000-0000-4000-8000-00000000000b'::uuid,
  'with the sub of B, current_user_id() is B''s profile id'
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

-- Control for the null above: the same sub resolves the moment its profile exists.
reset role;
select set_config('test.unknown_id',
  (select id::text from public.user_profiles where identity_sub = 'user_unknown'), true);
set local role authenticated;

select is(
  public.current_user_id(),
  current_setting('test.unknown_id')::uuid,
  'control: once created, the profile is who current_user_id() says they are'
);

select is(
  (select count(*)::int from public.actors),
  0,
  'a new person sees no one else''s actors'
);

-- The server: service_role writes the mirror; the constraints still hold.
reset role;
select set_config('request.jwt.claims', '{"role":"service_role"}', true);
set local role service_role;

select lives_ok(
  $$insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref)
    values ('20000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a',
            'fursona', 'luna', 'public', 'suspended', '10000000-0000-4000-8000-00000000000a')
    on conflict (actor_ref) do update set status = excluded.status, synced_at = now()$$,
  'service_role can upsert an actor, keyed on actor_ref'
);

select is(
  (select status from public.actors where actor_ref = '20000000-0000-4000-8000-00000000000a'),
  'suspended',
  'the server''s upsert took effect'
);

select lives_ok(
  $$insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref)
    values ('40000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a',
            'fursona', 'sol', 'public', 'active', '10000000-0000-4000-8000-00000000000a')$$,
  'control: a fursona can be recorded under its own user''s person'
);

select throws_ok(
  $$insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref)
    values ('40000000-0000-4000-8000-0000000000aa', '00000000-0000-4000-8000-00000000000a',
            'fursona', 'borrowed', 'public', 'active', '10000000-0000-4000-8000-00000000000b')$$,
  '23503',
  null,
  'a fursona of A cannot be recorded under B''s person'
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
  $$insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref)
    values ('60000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000a',
            'person', 'u-a2', 'private', 'active', null)$$,
  '23505',
  null,
  'a user has at most one person actor'
);

select lives_ok(
  format($$insert into public.actors (actor_ref, user_id, kind, handle, visibility, status, owner_ref)
    values ('60000000-0000-4000-8000-00000000000c', %L, 'person', 'u-c', 'private', 'active', null)$$,
    current_setting('test.unknown_id')),
  'control: a user with no person actor yet can get one'
);

select * from finish();
rollback;
