-- The audit log, adapted from Libra's baseline.
--
-- audit.enable_tracking(table) puts a row trigger on a table; every insert, update and delete
-- then lands in audit.logged_actions with who did it (current_user_id()) and the row before and
-- after. The schema is not exposed to the API (config.toml) and nothing in it is granted to anon
-- or authenticated: the log is read by the server and by operators at the database.
--
-- audit.anonymise_user(id) is the erasure path: it replaces a person's id everywhere it appears
-- in logged rows with a fixed placeholder, so the history of what happened survives but no
-- longer says who.

create schema audit;

revoke all on schema audit from public, anon, authenticated;
grant usage on schema audit to service_role;

create table audit.logged_actions (
  event_id bigint generated always as identity primary key,
  schema_name text not null,
  table_name text not null,
  -- Who did it: current_user_id() at the time, null for the server or a migration.
  user_id uuid,
  db_user text not null default session_user,
  action_type text not null check (action_type in ('INSERT', 'UPDATE', 'DELETE')),
  old_data jsonb,
  new_data jsonb,
  action_timestamp timestamptz not null default now(),
  transaction_id bigint default txid_current()
);

comment on table audit.logged_actions is
  'One row per tracked insert, update or delete. Written only by audit.log_changes().';

create index logged_actions_table_idx on audit.logged_actions (schema_name, table_name);
create index logged_actions_user_id_idx on audit.logged_actions (user_id) where user_id is not null;
create index logged_actions_timestamp_idx on audit.logged_actions using brin (action_timestamp);

alter table audit.logged_actions enable row level security;
revoke all on audit.logged_actions from public, anon, authenticated;
grant select on audit.logged_actions to service_role;

create function audit.log_changes() returns trigger
  language plpgsql security definer
  set search_path = ''
  as $$
declare
  v_user_id uuid := public.current_user_id();
begin
  if tg_op = 'INSERT' then
    insert into audit.logged_actions (schema_name, table_name, user_id, action_type, new_data)
    values (tg_table_schema, tg_table_name, v_user_id, 'INSERT', to_jsonb(new));
    return new;
  elsif tg_op = 'UPDATE' then
    -- An update that changes nothing is not an event.
    if to_jsonb(new) = to_jsonb(old) then
      return new;
    end if;
    insert into audit.logged_actions (schema_name, table_name, user_id, action_type, old_data, new_data)
    values (tg_table_schema, tg_table_name, v_user_id, 'UPDATE', to_jsonb(old), to_jsonb(new));
    return new;
  else
    insert into audit.logged_actions (schema_name, table_name, user_id, action_type, old_data)
    values (tg_table_schema, tg_table_name, v_user_id, 'DELETE', to_jsonb(old));
    return old;
  end if;
end;
$$;

revoke all on function audit.log_changes() from public, anon, authenticated;

create function audit.enable_tracking(target_table regclass) returns void
  language plpgsql
  set search_path = ''
  as $$
declare
  v_trigger_name text := replace(replace('audit_' || target_table::text, '.', '_'), '"', '');
begin
  execute format('drop trigger if exists %I on %s', v_trigger_name, target_table);
  execute format(
    'create trigger %I after insert or update or delete on %s '
    'for each row execute function audit.log_changes()',
    v_trigger_name, target_table
  );
end;
$$;

comment on function audit.enable_tracking(regclass) is
  'Log every insert, update and delete on the table to audit.logged_actions. Call it from a migration.';

revoke all on function audit.enable_tracking(regclass) from public, anon, authenticated;

create function audit.anonymise_user(target_user_id uuid) returns bigint
  language plpgsql security definer
  set search_path = ''
  as $$
declare
  v_id text := target_user_id::text;
  v_placeholder text := '00000000-0000-0000-0000-000000000000';
  v_count bigint;
begin
  if target_user_id is null then
    raise exception 'anonymise_user needs a user id' using errcode = '22004';
  end if;

  update audit.logged_actions
  set user_id = case when user_id = target_user_id then v_placeholder::uuid else user_id end,
      old_data = replace(old_data::text, v_id, v_placeholder)::jsonb,
      new_data = replace(new_data::text, v_id, v_placeholder)::jsonb
  where user_id = target_user_id
     or strpos(old_data::text, v_id) > 0
     or strpos(new_data::text, v_id) > 0;

  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

comment on function audit.anonymise_user(uuid) is
  'Replace the person''s id with 00000000-0000-0000-0000-000000000000 in every logged row (actor, old and new data). Returns the rows changed.';

revoke all on function audit.anonymise_user(uuid) from public, anon, authenticated;
grant execute on function audit.anonymise_user(uuid) to service_role;
