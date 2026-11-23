-- The `notes` resource type: an example for docs/resources.md, never shipped by a migration.
-- The pgTAP tests create the same type inside their own transaction. Load this by hand to try
-- the example against a local database; it is not in config.toml's seed paths.
insert into public.resource_types (key, capabilities)
values ('notes', array['read', 'edit'])
on conflict (key) do nothing;
