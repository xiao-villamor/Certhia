-- Several saved connections may use different credentials for the same host.
CREATE TABLE registry_profiles(
    id uuid PRIMARY KEY,registry_id uuid NOT NULL REFERENCES registries,name text NOT NULL,secret bytea
);
CREATE INDEX registry_profiles_order ON registry_profiles(lower(name),id);
ALTER TABLE registry_config DROP CONSTRAINT registry_config_registry_id_fkey,
    ADD FOREIGN KEY(registry_id) REFERENCES registry_profiles(id) ON DELETE CASCADE;
ALTER TABLE registry_catalog DROP CONSTRAINT registry_catalog_registry_id_fkey,
    ADD FOREIGN KEY(registry_id) REFERENCES registry_profiles(id) ON DELETE CASCADE;
ALTER TABLE registry_webhooks DROP CONSTRAINT registry_webhooks_registry_id_fkey,
    ADD FOREIGN KEY(registry_id) REFERENCES registry_profiles(id) ON DELETE CASCADE;
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_registry_id_fkey,
    ADD FOREIGN KEY(registry_id) REFERENCES registry_profiles(id) ON DELETE SET NULL;
ALTER TABLE schedules DROP CONSTRAINT schedules_registry_id_fkey,
    ADD FOREIGN KEY(registry_id) REFERENCES registry_profiles(id) ON DELETE SET NULL;
ALTER TABLE registries DROP COLUMN secret;
