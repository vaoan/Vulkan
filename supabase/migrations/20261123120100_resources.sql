-- Owned resources and delegated capabilities.
--
-- A body registers each kind of thing it owns in resource_types, with the capabilities that make
-- sense for it; manage-delegates and transfer exist on every type without being listed. Each
-- resource has one owner, who holds every capability. The owner (or a delegate holding
-- manage-delegates) hands capabilities to other people in resource_delegates. Operators hold
-- every capability on every resource.
--
-- Policies of a body's own tables call has_capability(type, id, capability). Delegations and
-- ownership change only through grant_capabilities, revoke_capabilities and transfer_ownership:
-- no client writes resource_delegates or operators, and resources takes only a person's insert of
-- their own resource. Every change is in the audit log.

-- ---------------------------------------------------------------------------
-- resource_types: written by migrations or the server; read by anyone signed in.
-- ---------------------------------------------------------------------------
create table public.resource_types (
  key text primary key,
  capabilities text[] not null default '{}',
  constraint resource_types_no_universal_capabilities
    check (not (capabilities && array['manage-delegates', 'transfer']))
);

comment on table public.resource_types is
  'Each kind of owned resource and the capabilities it offers. manage-delegates and transfer are implied on every type.';

alter table public.resource_types enable row level security;

revoke all on public.resource_types from anon, authenticated;
grant select on public.resource_types to authenticated;

create policy "anyone signed in reads the resource types"
  on public.resource_types for select to authenticated
  using (true);

-- ---------------------------------------------------------------------------
-- operators: seeded by migration or the server; a person can see only whether they are one.
-- ---------------------------------------------------------------------------
create table public.operators (
  user_id uuid primary key references public.user_profiles (id) on delete cascade,
  created_at timestamptz not null default now()
);

comment on table public.operators is
  'People who hold every capability on every resource. Written only by migrations or service_role.';

alter table public.operators enable row level security;

revoke all on public.operators from anon, authenticated;
grant select on public.operators to authenticated;

create policy "a person reads only their own operator row"
  on public.operators for select to authenticated
  using (user_id = public.current_user_id());

-- ---------------------------------------------------------------------------
-- resources: one row per owned thing, keyed on (type, id).
-- ---------------------------------------------------------------------------
create table public.resources (
  type text not null references public.resource_types (key),
  id uuid not null default gen_random_uuid(),
  owner_id uuid not null references public.user_profiles (id),
  created_at timestamptz not null default now(),
  primary key (type, id)
);

comment on table public.resources is
  'Owned resources. A person inserts their own; ownership moves only through transfer_ownership.';

create index resources_owner_id_idx on public.resources (owner_id);

alter table public.resources enable row level security;

revoke all on public.resources from anon, authenticated;
grant select on public.resources to authenticated;
grant insert (type, id, owner_id) on public.resources to authenticated;

create policy "a person creates resources they own"
  on public.resources for insert to authenticated
  with check (owner_id = public.current_user_id());

-- ---------------------------------------------------------------------------
-- resource_delegates: who holds what on a resource, besides its owner.
-- ---------------------------------------------------------------------------
create table public.resource_delegates (
  type text not null,
  id uuid not null,
  user_id uuid not null references public.user_profiles (id) on delete cascade,
  capabilities text[] not null check (cardinality(capabilities) > 0),
  granted_by uuid references public.user_profiles (id) on delete set null,
  granted_at timestamptz not null default now(),
  primary key (type, id, user_id),
  foreign key (type, id) references public.resources (type, id) on delete cascade
);

comment on table public.resource_delegates is
  'Capabilities delegated on a resource. Written only by grant_capabilities, revoke_capabilities and transfer_ownership.';

create index resource_delegates_user_id_idx on public.resource_delegates (user_id);

alter table public.resource_delegates enable row level security;

revoke all on public.resource_delegates from anon, authenticated;
grant select on public.resource_delegates to authenticated;

-- The owner never has a delegate row: they already hold everything.
create function public.resource_delegates_not_owner() returns trigger
  language plpgsql
  set search_path = ''
  as $$
begin
  if exists (
    select 1 from public.resources r
    where r.type = new.type and r.id = new.id and r.owner_id = new.user_id
  ) then
    raise exception 'the owner of a resource cannot be its delegate' using errcode = '23514';
  end if;
  return new;
end;
$$;

revoke all on function public.resource_delegates_not_owner() from public, anon, authenticated;

create trigger resource_delegates_not_owner
  before insert or update on public.resource_delegates
  for each row execute function public.resource_delegates_not_owner();

-- ---------------------------------------------------------------------------
-- has_capability: the one question every policy asks.
-- ---------------------------------------------------------------------------
create function public.has_capability(resource_type text, resource_id uuid, capability text)
  returns boolean
  language sql stable security definer
  set search_path = ''
  as $$
  select coalesce((
    select r.owner_id = me.id
        or exists (select 1 from public.operators o where o.user_id = me.id)
        or exists (
          select 1 from public.resource_delegates d
          where d.type = r.type and d.id = r.id and d.user_id = me.id
            and has_capability.capability = any (d.capabilities)
        )
    from public.resources r
    cross join (select public.current_user_id() as id) me
    where r.type = resource_type and r.id = resource_id and me.id is not null
  ), false)
$$;

comment on function public.has_capability(text, uuid, text) is
  'True when the caller owns the resource, is an operator, or was delegated the capability on it. False for a resource that does not exist or a caller with no profile.';

revoke all on function public.has_capability(text, uuid, text) from public, anon, authenticated;
grant execute on function public.has_capability(text, uuid, text) to authenticated, service_role;

-- Reading: a person sees the resources they own or hold something on, and the delegations they
-- hold or manage. Operators see everything.
create policy "a person reads resources they own or hold capabilities on"
  on public.resources for select to authenticated
  using (
    owner_id = public.current_user_id()
    or exists (select 1 from public.operators o where o.user_id = public.current_user_id())
    or exists (
      select 1 from public.resource_delegates d
      where d.type = resources.type and d.id = resources.id and d.user_id = public.current_user_id()
    )
  );

create policy "a person reads their own delegations and those they manage"
  on public.resource_delegates for select to authenticated
  using (
    user_id = public.current_user_id()
    or public.has_capability(type, id, 'manage-delegates')
  );

-- ---------------------------------------------------------------------------
-- The writers.
-- ---------------------------------------------------------------------------
create function public.grant_capabilities(
  resource_type text, resource_id uuid, grantee_id uuid, capabilities text[]
) returns void
  language plpgsql security definer
  set search_path = ''
  as $$
declare
  v_me uuid := public.current_user_id();
  v_owner uuid;
  v_offered text[];
  v_held text[];
begin
  select r.owner_id, t.capabilities || array['manage-delegates', 'transfer']
  into v_owner, v_offered
  from public.resources r
  join public.resource_types t on t.key = r.type
  where r.type = resource_type and r.id = resource_id;

  if v_me is null or v_owner is null then
    raise exception 'not permitted' using errcode = '42501';
  end if;

  if coalesce(cardinality(grant_capabilities.capabilities), 0) = 0
     or not (grant_capabilities.capabilities <@ v_offered) then
    raise exception 'type % does not offer every capability in %', resource_type, grant_capabilities.capabilities
      using errcode = '22023';
  end if;

  if grantee_id = v_me or grantee_id = v_owner then
    raise exception 'nobody grants to themselves or to the owner' using errcode = '42501';
  end if;

  if v_owner <> v_me and not exists (select 1 from public.operators o where o.user_id = v_me) then
    select d.capabilities into v_held
    from public.resource_delegates d
    where d.type = resource_type and d.id = resource_id and d.user_id = v_me;

    if v_held is null
       or not ('manage-delegates' = any (v_held))
       or not (grant_capabilities.capabilities <@ v_held) then
      raise exception 'not permitted' using errcode = '42501';
    end if;
  end if;

  insert into public.resource_delegates as d (type, id, user_id, capabilities, granted_by)
  values (
    resource_type, resource_id, grantee_id,
    array(select distinct c from unnest(grant_capabilities.capabilities) c order by c),
    v_me
  )
  on conflict (type, id, user_id) do update
  set capabilities = array(
        select distinct c from unnest(d.capabilities || excluded.capabilities) c order by c),
      granted_by = excluded.granted_by,
      granted_at = now();
end;
$$;

comment on function public.grant_capabilities(text, uuid, uuid, text[]) is
  'Add capabilities to a person on a resource. The owner or an operator may grant any; a delegate with manage-delegates may grant only what they hold.';

create function public.revoke_capabilities(
  resource_type text, resource_id uuid, grantee_id uuid, capabilities text[]
) returns void
  language plpgsql security definer
  set search_path = ''
  as $$
declare
  v_me uuid := public.current_user_id();
  v_remaining text[];
begin
  if v_me is null or not public.has_capability(resource_type, resource_id, 'manage-delegates') then
    raise exception 'not permitted' using errcode = '42501';
  end if;

  select array(
    select c from unnest(d.capabilities) c
    where not (c = any (revoke_capabilities.capabilities))
    order by c)
  into v_remaining
  from public.resource_delegates d
  where d.type = resource_type and d.id = resource_id and d.user_id = grantee_id
  for update;

  if v_remaining is null then
    return;
  elsif cardinality(v_remaining) = 0 then
    delete from public.resource_delegates d
    where d.type = resource_type and d.id = resource_id and d.user_id = grantee_id;
  else
    update public.resource_delegates d
    set capabilities = v_remaining
    where d.type = resource_type and d.id = resource_id and d.user_id = grantee_id;
  end if;
end;
$$;

comment on function public.revoke_capabilities(text, uuid, uuid, text[]) is
  'Remove capabilities from a person on a resource; removing the last one removes the delegation. Needs the owner, an operator or manage-delegates.';

create function public.transfer_ownership(resource_type text, resource_id uuid, new_owner_id uuid)
  returns void
  language plpgsql security definer
  set search_path = ''
  as $$
begin
  if public.current_user_id() is null
     or not public.has_capability(resource_type, resource_id, 'transfer') then
    raise exception 'not permitted' using errcode = '42501';
  end if;

  if new_owner_id is null
     or exists (select 1 from public.resources r
                where r.type = resource_type and r.id = resource_id and r.owner_id = new_owner_id) then
    raise exception 'the resource already belongs to that person' using errcode = '22023';
  end if;

  -- The new owner holds everything; a delegation they had would only go stale.
  delete from public.resource_delegates d
  where d.type = resource_type and d.id = resource_id and d.user_id = new_owner_id;

  update public.resources r
  set owner_id = new_owner_id
  where r.type = resource_type and r.id = resource_id;
end;
$$;

comment on function public.transfer_ownership(text, uuid, uuid) is
  'Give a resource to another person. Needs the owner, an operator or the transfer capability. The previous owner keeps nothing unless granted afterwards.';

revoke all on function public.grant_capabilities(text, uuid, uuid, text[]) from public, anon, authenticated;
revoke all on function public.revoke_capabilities(text, uuid, uuid, text[]) from public, anon, authenticated;
revoke all on function public.transfer_ownership(text, uuid, uuid) from public, anon, authenticated;
grant execute on function public.grant_capabilities(text, uuid, uuid, text[]) to authenticated;
grant execute on function public.revoke_capabilities(text, uuid, uuid, text[]) to authenticated;
grant execute on function public.transfer_ownership(text, uuid, uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- Every change to ownership, delegation or operators is logged.
-- ---------------------------------------------------------------------------
select audit.enable_tracking('public.resources');
select audit.enable_tracking('public.resource_delegates');
select audit.enable_tracking('public.operators');
