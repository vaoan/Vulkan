-- Owned resources and delegated capabilities: who may do what to a resource, and the only ways
-- that changes. People are impersonated through request.jwt.claims, as in identity.test.sql.
-- The `notes` type exists only here (and in supabase/seed/example-resource.sql): no migration
-- ships it. Everything runs in one transaction and is rolled back.
begin;

select plan(73);

-- Fixtures, written as the owner (RLS does not apply).
insert into public.user_profiles (id, identity_sub) values
  ('00000000-0000-4000-8000-00000000000a', 'user_a'),
  ('00000000-0000-4000-8000-00000000000b', 'user_b'),
  ('00000000-0000-4000-8000-00000000000c', 'user_c'),
  ('00000000-0000-4000-8000-00000000000d', 'user_d'),
  ('00000000-0000-4000-8000-00000000000e', 'user_e'),
  ('00000000-0000-4000-8000-00000000000f', 'user_f');

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

select ok(
  not public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'publish'),
  'not even the owner has a capability the type does not register'
);

-- Each writer on a resource that does not exist: not permitted, as for a stranger.
select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-0000000000ff', '00000000-0000-4000-8000-00000000000b', array['edit'])$$,
  '42501', null, 'grant on a resource that does not exist is not permitted'
);

select throws_ok(
  $$select public.revoke_capabilities('notes', '90000000-0000-4000-8000-0000000000ff', '00000000-0000-4000-8000-00000000000b', array['edit'])$$,
  '42501', null, 'revoke on a resource that does not exist is not permitted'
);

select throws_ok(
  $$select public.transfer_ownership('notes', '90000000-0000-4000-8000-0000000000ff', '00000000-0000-4000-8000-00000000000b')$$,
  '42501', null, 'transfer of a resource that does not exist is not permitted'
);

-- Malformed arguments are refused before anything else.
select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000b', null)$$,
  '22023', null, 'grant refuses a null capabilities array'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000b', array[]::text[])$$,
  '22023', null, 'grant refuses an empty capabilities array'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000b', array['edit', null])$$,
  '22023', null, 'grant refuses a capabilities array with a null element'
);

select throws_ok(
  $$select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000b', null)$$,
  '22023', null, 'revoke refuses a null capabilities array'
);

select throws_ok(
  $$select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000b', array[]::text[])$$,
  '22023', null, 'revoke refuses an empty capabilities array'
);

select throws_ok(
  $$select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000b', array['edit', null])$$,
  '22023', null, 'revoke refuses a capabilities array with a null element'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001', null, array['edit'])$$,
  '22023', null, 'grant refuses a null grantee'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-0000000000ee', array['edit'])$$,
  '22023', null, 'grant refuses a grantee with no profile'
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

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000d', array['publish'])$$,
  '42501', null, 'a stranger is refused as not permitted even for a capability the type lacks'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-0000000000ff', '00000000-0000-4000-8000-00000000000d', array['publish'])$$,
  '42501', null, 'a stranger gets the same refusal for a resource that does not exist'
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

select ok(
  not public.has_capability('notes', '90000000-0000-4000-8000-000000000001', 'publish'),
  'not even an operator has a capability the type does not register'
);

select lives_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000d', array['read'])$$,
  'the operator C grants on A''s note'
);

select lives_ok(
  $$select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000d', array['read'])$$,
  'the operator C revokes on A''s note'
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

select throws_ok(
  $$select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000d', array['edit'])$$,
  '22023', null, 'a revoke from a person with no delegation changes nothing and is refused'
);

reset role;

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

select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;

select throws_ok(
  $$select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000b', array['edit', 'read'])$$,
  '22023', null, 'a revoke of capabilities the person does not hold changes nothing and is refused'
);

reset role;

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

select is(
  (select capabilities from public.resource_delegates where user_id = '00000000-0000-4000-8000-00000000000d'),
  array['edit'],
  'a delegate with only working capabilities keeps them across a transfer'
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
-- A transfer keeps the delegates' working capabilities and strips the admin ones.
-- A's second note: B holds edit, transfer and manage-delegates; F holds only manage-delegates;
-- E, the next owner, holds read.
-- ---------------------------------------------------------------------------
reset role;
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;
insert into public.resources (type, id, owner_id) values ('notes', '90000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-00000000000a');
select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-00000000000b', array['edit', 'transfer', 'manage-delegates']);
select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-00000000000f', array['manage-delegates']);
select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-00000000000e', array['read']);

reset role;
select set_config('request.jwt.claims', '{"sub":"user_b","role":"authenticated"}', true);
set local role authenticated;

select ok(
  public.has_capability('notes', '90000000-0000-4000-8000-000000000002', 'transfer'),
  'control: before the transfer, B holds transfer'
);

select lives_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-00000000000d', array['edit'])$$,
  'control: before the transfer, B can grant on the note'
);

reset role;
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;

select lives_ok(
  $$select public.transfer_ownership('notes', '90000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-00000000000e')$$,
  'A transfers the second note to E'
);

reset role;
select is(
  (select capabilities from public.resource_delegates
    where id = '90000000-0000-4000-8000-000000000002' and user_id = '00000000-0000-4000-8000-00000000000b'),
  array['edit'],
  'B keeps edit and loses transfer and manage-delegates'
);

select is(
  (select count(*)::int from public.resource_delegates
    where id = '90000000-0000-4000-8000-000000000002' and user_id in ('00000000-0000-4000-8000-00000000000f', '00000000-0000-4000-8000-00000000000e')),
  0,
  'a delegate left with nothing is removed, and so is the new owner''s delegation'
);

select set_config('request.jwt.claims', '{"sub":"user_b","role":"authenticated"}', true);
set local role authenticated;

select throws_ok(
  $$select public.transfer_ownership('notes', '90000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-00000000000b')$$,
  '42501', null, 'after the transfer, B can no longer transfer the note'
);

select throws_ok(
  $$select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000002', '00000000-0000-4000-8000-00000000000d', array['edit'])$$,
  '42501', null, 'after the transfer, B can no longer grant on the note'
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
