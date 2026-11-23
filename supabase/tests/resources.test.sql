-- Owned resources and delegated capabilities: who may do what to a resource, and the only ways
-- that changes. People are impersonated through request.jwt.claims, as in identity.test.sql.
-- The `notes` type exists only here (and in supabase/seed/example-resource.sql): no migration
-- ships it. Everything runs in one transaction and is rolled back.
begin;

select plan(46);

-- Fixtures, written as the owner (RLS does not apply).
insert into public.user_profiles (id, identity_sub) values
  ('00000000-0000-4000-8000-00000000000a', 'user_a'),
  ('00000000-0000-4000-8000-00000000000b', 'user_b'),
  ('00000000-0000-4000-8000-00000000000c', 'user_c'),
  ('00000000-0000-4000-8000-00000000000d', 'user_d');

insert into public.resource_types (key, capabilities) values ('notes', array['read', 'edit']);
insert into public.operators (user_id) values ('00000000-0000-4000-8000-00000000000c');

-- The guarded functions are security definer, with an empty search_path.
select is(
  (select count(*)::int from pg_proc
    where oid in ('public.has_capability(text, uuid, text)'::regprocedure,
                  'public.grant_capabilities(text, uuid, uuid, text[])'::regprocedure,
                  'public.revoke_capabilities(text, uuid, uuid, text[])'::regprocedure,
                  'public.transfer_ownership(text, uuid, uuid)'::regprocedure)
      and prosecdef and proconfig @> array['search_path=""']),
  4,
  'has_capability and the three writers are security definer with search_path empty'
);

-- ---------------------------------------------------------------------------
-- A creates a note. Only for themselves; never updated or deleted directly.
-- ---------------------------------------------------------------------------
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;

select lives_ok(
  $$insert into public.resources (type, id, owner_id)
    values ('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000a')$$,
  'A can create a resource they own'
);

select throws_ok(
  $$insert into public.resources (type, id, owner_id)
    values ('notes', '90000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-00000000000b')$$,
  '42501',
  null,
  'A cannot create a resource owned by B'
);

select throws_ok(
  $$update public.resources set owner_id = '00000000-0000-4000-8000-00000000000b'
    where id = '90000000-0000-4000-8000-000000000001'$$,
  '42501',
  null,
  'A cannot update a resource directly, not even their own'
);

select throws_ok(
  $$delete from public.resources where id = '90000000-0000-4000-8000-000000000001'$$,
  '42501',
  null,
  'A cannot delete a resource directly'
);

select is((select count(*)::int from public.resources), 1, 'A sees their own note');

select is(
  (select capabilities from public.resource_types where key = 'notes'),
  array['read', 'edit'],
  'resource types are readable'
);

select throws_ok(
  $$insert into public.resource_types (key, capabilities) values ('mine', array['x'])$$,
  '42501',
  null,
  'authenticated cannot register a resource type'
);

select ok(
  public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'edit')
  and public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'manage-delegates')
  and public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'transfer'),
  'the owner A has every capability on their note'
);

-- Direct writes to the delegation tables are refused, whoever tries.
select throws_ok(
  $$insert into public.resource_delegates (type, id, user_id, capabilities, granted_by)
    values ('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000b',
            array['edit'], '00000000-0000-4000-8000-00000000000a')$$,
  '42501',
  null,
  'a direct insert into resource_delegates is refused, even for the owner'
);

select throws_ok(
  $$insert into public.operators (user_id) values ('00000000-0000-4000-8000-00000000000a')$$,
  '42501',
  null,
  'nobody makes themselves an operator'
);

-- ---------------------------------------------------------------------------
-- B is a stranger; C is an operator.
-- ---------------------------------------------------------------------------
reset role;
select set_config('request.jwt.claims', '{"sub":"user_b","role":"authenticated"}', true);
set local role authenticated;

select ok(
  not (public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'read')
    or public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'edit')
    or public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'manage-delegates')
    or public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'transfer')),
  'the stranger B has no capability on A''s note'
);

select is((select count(*)::int from public.resources), 0, 'B does not see A''s note');

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000d', array['edit'])$$,
  '42501',
  null,
  'the stranger B cannot grant on A''s note'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"user_c","role":"authenticated"}', true);
set local role authenticated;

select ok(
  public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'read')
  and public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'edit')
  and public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'manage-delegates')
  and public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'transfer'),
  'the operator C has every capability on A''s note'
);

select is((select count(*)::int from public.resources), 1, 'the operator C sees A''s note');

select ok(
  not public.has_capability('notes', '90000000-0000-4000-8000-0000000000ff', 'read'),
  'nobody, not even an operator, has a capability on a resource that does not exist'
);

-- ---------------------------------------------------------------------------
-- A grants B edit.
-- ---------------------------------------------------------------------------
reset role;
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;

select lives_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000b', array['edit'])$$,
  'A grants B edit'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000b', array['publish'])$$,
  '22023',
  null,
  'a capability the type does not register cannot be granted'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000a', array['edit'])$$,
  '42501',
  null,
  'the owner cannot grant to themselves'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"user_b","role":"authenticated"}', true);
set local role authenticated;

select ok(
  public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'edit'),
  'B now has edit'
);

select ok(
  not public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'transfer'),
  'B does not have transfer'
);

select is((select count(*)::int from public.resources), 1, 'a delegate sees the resource');

select is(
  (select capabilities from public.resource_delegates where user_id = '00000000-0000-4000-8000-00000000000b'),
  array['edit'],
  'B reads their own delegation'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000d', array['edit'])$$,
  '42501',
  null,
  'B, holding edit but not manage-delegates, cannot grant edit'
);

-- ---------------------------------------------------------------------------
-- B holds manage-delegates and edit, and grants on to D.
-- ---------------------------------------------------------------------------
reset role;
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;

select lives_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000b', array['manage-delegates'])$$,
  'A grants B manage-delegates'
);

select is(
  (select capabilities from public.resource_delegates where user_id = '00000000-0000-4000-8000-00000000000b'),
  array['edit', 'manage-delegates'],
  'a second grant adds to B''s capabilities in one row'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"user_b","role":"authenticated"}', true);
set local role authenticated;

select lives_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000d', array['edit'])$$,
  'B, holding manage-delegates and edit, grants D edit'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000d', array['transfer'])$$,
  '42501',
  null,
  'B cannot grant transfer, which B lacks'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000b', array['edit'])$$,
  '42501',
  null,
  'B cannot grant to themselves, even a capability B holds'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000a', array['edit'])$$,
  '42501',
  null,
  'B cannot grant to the owner'
);

select throws_ok(
  $$update public.resource_delegates set capabilities = array['edit', 'transfer']
    where user_id = '00000000-0000-4000-8000-00000000000b'$$,
  '42501',
  null,
  'B cannot rewrite their own delegation directly'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"user_d","role":"authenticated"}', true);
set local role authenticated;

select ok(
  public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'edit'),
  'D now has edit'
);

-- ---------------------------------------------------------------------------
-- Revoking.
-- ---------------------------------------------------------------------------
select throws_ok(
  $$select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000b', array['edit'])$$,
  '42501',
  null,
  'D, without manage-delegates, cannot revoke'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"user_b","role":"authenticated"}', true);
set local role authenticated;

select lives_ok(
  $$select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000d', array['edit'])$$,
  'B, holding manage-delegates, revokes D''s edit'
);

reset role;
select is(
  (select count(*)::int from public.resource_delegates where user_id = '00000000-0000-4000-8000-00000000000d'),
  0,
  'revoking everything from D removes D''s row'
);

select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;

select lives_ok(
  $$select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000b', array['edit'])$$,
  'A revokes B''s edit'
);

reset role;
select is(
  (select capabilities from public.resource_delegates where user_id = '00000000-0000-4000-8000-00000000000b'),
  array['manage-delegates'],
  'a partial revoke keeps the rest of B''s capabilities'
);

-- ---------------------------------------------------------------------------
-- Transferring ownership.
-- ---------------------------------------------------------------------------
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;
select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-00000000000d', array['edit']);

reset role;
select set_config('request.jwt.claims', '{"sub":"user_d","role":"authenticated"}', true);
set local role authenticated;

select throws_ok(
  $$select public.transfer_ownership('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000d')$$,
  '42501',
  null,
  'D, a delegate without transfer, cannot transfer the note'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;

select lives_ok(
  $$select public.transfer_ownership('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000b')$$,
  'A transfers the note to B'
);

select ok(
  not public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'read'),
  'A keeps nothing after the transfer'
);

reset role;
select is(
  (select owner_id from public.resources where id = '90000000-0000-4000-8000-000000000001'),
  '00000000-0000-4000-8000-00000000000b'::uuid,
  'B is the owner'
);

select is(
  (select count(*)::int from public.resource_delegates where user_id = '00000000-0000-4000-8000-00000000000b'),
  0,
  'the new owner keeps no delegate row'
);

-- A delegate holding transfer may transfer: the positive control for D's refusal above.
select set_config('request.jwt.claims', '{"sub":"user_b","role":"authenticated"}', true);
set local role authenticated;
select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-00000000000d', array['transfer']);

reset role;
select set_config('request.jwt.claims', '{"sub":"user_d","role":"authenticated"}', true);
set local role authenticated;

select lives_ok(
  $$select public.transfer_ownership('notes', '90000000-0000-4000-8000-000000000001',
      '00000000-0000-4000-8000-00000000000d')$$,
  'D, holding transfer, transfers the note to themselves'
);

-- ---------------------------------------------------------------------------
-- No JWT: nothing.
-- ---------------------------------------------------------------------------
reset role;
select set_config('request.jwt.claims', '', true);
set local role anon;

select throws_ok(
  $$select public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'read')$$,
  '42501',
  null,
  'anon cannot call has_capability'
);

select throws_ok(
  'select count(*) from public.resources',
  '42501',
  null,
  'anon cannot read resources'
);

select * from finish();
rollback;
