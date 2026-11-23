# Owned resources

Every resource a body keeps has one owner. The owner holds every capability on it, can hand
capabilities to other people, and can give the resource away. Operators hold every capability on
every resource. A body's tables ask one question in their policies:
`public.has_capability(type, id, capability)`.

## Declare a type and its capabilities

A migration registers the type with the capabilities that make sense for it.
`manage-delegates` (grant and revoke on the resource) and `transfer` (give it away) exist on
every type and are never listed.

```sql
insert into public.resource_types (key, capabilities)
values ('notes', array['read', 'edit']);
```

The `notes` type is only an example: `supabase/seed/example-resource.sql` holds it, and no
migration ships it.

## Give the type a table

The body's own table points at `public.resources`, so every row has an owner. The row in
`resources` is created first, by the person who will own it.

```sql
create table public.notes (
  type text not null default 'notes' check (type = 'notes'),
  id uuid not null,
  body text not null,
  primary key (id),
  foreign key (type, id) references public.resources (type, id) on delete cascade
);

alter table public.notes enable row level security;

revoke all on public.notes from anon, authenticated;
grant select, insert, update (body) on public.notes to authenticated;

create policy "notes are read by whoever holds read"
  on public.notes for select to authenticated
  using (public.has_capability(type, id, 'read'));

create policy "notes are created by their owner"
  on public.notes for insert to authenticated
  with check (exists (
    select 1 from public.resources r
    where r.type = notes.type and r.id = notes.id and r.owner_id = public.current_user_id()
  ));

create policy "notes are edited by whoever holds edit"
  on public.notes for update to authenticated
  using (public.has_capability(type, id, 'edit'))
  with check (public.has_capability(type, id, 'edit'));

select audit.enable_tracking('public.notes');
```

Creating a note from the client is two inserts, the resource then the row:

```sql
insert into public.resources (type, id, owner_id) values ('notes', :id, public.current_user_id());
insert into public.notes (id, body) values (:id, 'hello');
```

## Delegate, revoke, transfer

Nobody writes `resource_delegates`, `operators` or the owner of a resource directly. These three
functions are the only writers, and each change lands in `audit.logged_actions`:

- `grant_capabilities(type, id, user_id, capabilities)`: the owner or an operator grants any
  capability the type offers; a delegate holding `manage-delegates` grants only what they hold.
  Nobody grants to themselves or to the owner.
- `revoke_capabilities(type, id, user_id, capabilities)`: the owner, an operator or a holder of
  `manage-delegates`. Revoking a person's last capability removes their delegation.
- `transfer_ownership(type, id, new_owner_id)`: the owner, an operator or a holder of `transfer`.
  The previous owner keeps nothing unless someone grants it back.

Operators are added by a migration or by the server with `service_role`.

## The audit log

`audit.enable_tracking(table)` logs every insert, update and delete of a table. The `audit`
schema is not exposed to the API and no client can read it. To erase a person from the history,
the server calls `audit.anonymise_user(user_id)`, which replaces their id in every logged row
with `00000000-0000-0000-0000-000000000000`.
