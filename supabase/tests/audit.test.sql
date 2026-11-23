-- The audit log: every grant, revoke and transfer leaves a row, clients cannot reach it, and a
-- person can be anonymised out of it. Everything runs in one transaction and is rolled back.
begin;

select plan(18);

insert into public.user_profiles (id, identity_sub) values
  ('00000000-0000-4000-8000-00000000000a', 'user_a'),
  ('00000000-0000-4000-8000-00000000000b', 'user_b'),
  ('00000000-0000-4000-8000-00000000000d', 'user_d');

insert into public.resource_types (key, capabilities) values ('notes', array['read', 'edit']);
insert into public.resources (type, id, owner_id)
  values ('notes', '90000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-00000000000a');

-- The schema is closed to clients.
select ok(
  not has_schema_privilege('anon', 'audit', 'usage')
  and not has_schema_privilege('authenticated', 'audit', 'usage'),
  'anon and authenticated have no usage on the audit schema'
);

select ok(
  not has_table_privilege('authenticated', 'audit.logged_actions', 'select')
  and not has_table_privilege('anon', 'audit.logged_actions', 'select'),
  'anon and authenticated cannot read audit.logged_actions'
);

select ok(
  not has_function_privilege('authenticated', 'audit.anonymise_user(uuid)', 'execute')
  and not has_function_privilege('anon', 'audit.anonymise_user(uuid)', 'execute')
  and has_function_privilege('service_role', 'audit.anonymise_user(uuid)', 'execute'),
  'only service_role (and the owner) may call audit.anonymise_user'
);

select ok(
  not has_function_privilege('authenticated', 'audit.enable_tracking(regclass)', 'execute')
  and not has_function_privilege('anon', 'audit.enable_tracking(regclass)', 'execute'),
  'anon and authenticated cannot call audit.enable_tracking'
);

-- Each writer leaves exactly one row. The count is taken as the owner, between calls.
create temporary table seen (n int) on commit drop;
insert into seen select count(*) from audit.logged_actions;

select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;
select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-00000000000b', array['edit', 'manage-delegates']);
reset role;

select is(
  (select count(*)::int from audit.logged_actions) - (select n from seen),
  1,
  'a grant leaves one audit row'
);

select is(
  (select user_id from audit.logged_actions order by event_id desc limit 1),
  '00000000-0000-4000-8000-00000000000a'::uuid,
  'the row records who granted'
);

select ok(
  (select old_data is null
      and new_data ->> 'user_id' = '00000000-0000-4000-8000-00000000000b'
      and new_data -> 'capabilities' = '["edit", "manage-delegates"]'::jsonb
    from audit.logged_actions order by event_id desc limit 1),
  'a first grant is logged as an insert with the new delegation as new_data'
);

update seen set n = (select count(*) from audit.logged_actions);
select set_config('request.jwt.claims', '{"sub":"user_b","role":"authenticated"}', true);
set local role authenticated;
select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-00000000000d', array['edit']);
reset role;

select is(
  (select count(*)::int from audit.logged_actions) - (select n from seen),
  1,
  'a grant by a delegate leaves one audit row'
);

update seen set n = (select count(*) from audit.logged_actions);
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;
select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-00000000000b', array['edit']);
reset role;

select is(
  (select count(*)::int from audit.logged_actions) - (select n from seen),
  1,
  'a revoke leaves one audit row'
);

select ok(
  (select action_type = 'UPDATE'
      and old_data -> 'capabilities' = '["edit", "manage-delegates"]'::jsonb
      and new_data -> 'capabilities' = '["manage-delegates"]'::jsonb
    from audit.logged_actions order by event_id desc limit 1),
  'a partial revoke is logged with the capabilities before and after'
);

update seen set n = (select count(*) from audit.logged_actions);
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;
select public.revoke_capabilities('notes', '90000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-00000000000d', array['edit']);
reset role;

select is(
  (select action_type from audit.logged_actions order by event_id desc limit 1),
  'DELETE',
  'revoking everything is logged as the delegation''s deletion'
);

-- Before the transfer, D (the next owner) holds read and B holds edit and manage-delegates.
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;
select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-00000000000d', array['read']);
select public.grant_capabilities('notes', '90000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-00000000000b', array['edit']);
reset role;

update seen set n = (select count(*) from audit.logged_actions);
select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;
select public.transfer_ownership('notes', '90000000-0000-4000-8000-000000000001',
  '00000000-0000-4000-8000-00000000000d');
reset role;

select is(
  (select count(*)::int from audit.logged_actions) - (select n from seen),
  3,
  'a transfer logs the owner change and one row per delegation it changes: the new owner''s removed, B''s stripped'
);

-- Anonymising B. Control first: B really is in the log, as actor and inside row data.
create function pg_temp.rows_with(person uuid) returns int language sql as $$
  select count(*)::int from audit.logged_actions
  where user_id = person
     or coalesce(old_data::text, '') like '%' || person::text || '%'
     or coalesce(new_data::text, '') like '%' || person::text || '%'
$$;

select ok(
  pg_temp.rows_with('00000000-0000-4000-8000-00000000000b') >= 2
  and exists (select 1 from audit.logged_actions where user_id = '00000000-0000-4000-8000-00000000000b'),
  'control: B appears in the log, as the actor and in row data'
);

select set_config('request.jwt.claims', '{"sub":"user_a","role":"authenticated"}', true);
set local role authenticated;
select throws_ok(
  $$select audit.anonymise_user('00000000-0000-4000-8000-00000000000b')$$,
  '42501',
  null,
  'authenticated cannot anonymise anyone'
);
reset role;

select set_config('test.expected',
  pg_temp.rows_with('00000000-0000-4000-8000-00000000000b')::text, true);
select set_config('request.jwt.claims', '{"role":"service_role"}', true);
set local role service_role;
select is(
  audit.anonymise_user('00000000-0000-4000-8000-00000000000b'),
  current_setting('test.expected')::bigint,
  'anonymise_user returns the number of rows it changed'
);
reset role;

select is(
  pg_temp.rows_with('00000000-0000-4000-8000-00000000000b'),
  0,
  'after anonymise_user(B), no logged row contains B''s id'
);

select ok(
  pg_temp.rows_with('00000000-0000-0000-0000-000000000000') >= 2,
  'B''s rows now carry the fixed placeholder'
);

select ok(
  pg_temp.rows_with('00000000-0000-4000-8000-00000000000a') > 0,
  'anonymising B leaves A''s rows alone'
);

select * from finish();
rollback;
