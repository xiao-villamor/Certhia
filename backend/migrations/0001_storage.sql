CREATE TABLE registries (
    id uuid PRIMARY KEY, host text UNIQUE NOT NULL, name text NOT NULL, secret bytea
);
CREATE TABLE repositories (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    registry_id uuid NOT NULL REFERENCES registries, name text NOT NULL,
    UNIQUE(registry_id, name)
);
CREATE TABLE digests (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    digest text UNIQUE NOT NULL, os text, arch text, size bigint, created_at timestamptz,
    first_scanned_at timestamptz NOT NULL DEFAULT now(), inventory_complete boolean NOT NULL DEFAULT false
);
CREATE TABLE repository_digests (
    repository_id bigint REFERENCES repositories, digest_id bigint REFERENCES digests,
    PRIMARY KEY(repository_id, digest_id)
);
CREATE INDEX ON repository_digests(digest_id, repository_id);
CREATE TABLE image_tags (
    repository_id bigint NOT NULL, tag text NOT NULL, platform text NOT NULL, digest_id bigint NOT NULL,
    updated_at timestamptz NOT NULL, PRIMARY KEY(repository_id, tag, platform),
    FOREIGN KEY(repository_id, digest_id) REFERENCES repository_digests
);
CREATE TABLE ecosystems (id smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name text NOT NULL UNIQUE);
CREATE TABLE severities (id smallint PRIMARY KEY, name text NOT NULL UNIQUE);
INSERT INTO severities VALUES (0,'unknown'), (1,'low'), (2,'medium'), (3,'high'), (4,'critical');
CREATE TABLE packages (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, ecosystem_id smallint NOT NULL REFERENCES ecosystems,
    name text NOT NULL, version text NOT NULL, purl text, UNIQUE NULLS NOT DISTINCT(ecosystem_id,name,version,purl)
);
CREATE INDEX ON packages(name,id);
CREATE TABLE digest_packages (
    digest_id bigint REFERENCES digests, package_id integer REFERENCES packages,
    layer_index integer NOT NULL DEFAULT -1, PRIMARY KEY(digest_id,package_id,layer_index)
) PARTITION BY HASH(digest_id);
CREATE TABLE advisories (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, external_id text NOT NULL, source text NOT NULL,
    severity_id smallint NOT NULL REFERENCES severities, cvss_score real, cvss_vector text,
    epss real, kev boolean, summary text, description text, refs jsonb, published_at timestamptz,
    modified_at timestamptz, UNIQUE(external_id,source)
);
CREATE TABLE scan_directory (
    scan_no bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, id uuid NOT NULL UNIQUE, queued_at timestamptz NOT NULL,
    UNIQUE(id,queued_at)
);
CREATE TABLE scans (
    id uuid NOT NULL, queued_at timestamptz NOT NULL, digest_id bigint REFERENCES digests,
    repository_id bigint REFERENCES repositories, reference text NOT NULL, platform text NOT NULL,
    scanner text, scanner_version text, scanner_db_version text, status text NOT NULL,
    priority integer NOT NULL DEFAULT 0, started_at timestamptz, finished_at timestamptz,
    error text, raw_report_ref text, PRIMARY KEY(queued_at,id),
    FOREIGN KEY(id,queued_at) REFERENCES scan_directory(id,queued_at)
) PARTITION BY RANGE(queued_at);
CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY, created_at timestamptz NOT NULL DEFAULT now(),
    action text NOT NULL, resource text NOT NULL, detail text NOT NULL, PRIMARY KEY(created_at,id)
) PARTITION BY RANGE(created_at);
CREATE TABLE fix_versions(id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, version text NOT NULL UNIQUE);
CREATE TABLE findings (
    digest_id bigint REFERENCES digests, first_seen_scan_id bigint NOT NULL REFERENCES scan_directory,
    last_seen_scan_id bigint NOT NULL REFERENCES scan_directory, resolved_scan_id bigint REFERENCES scan_directory,
    package_id integer REFERENCES packages, advisory_id integer REFERENCES advisories, fixed_in integer REFERENCES fix_versions,
    PRIMARY KEY(digest_id,package_id,advisory_id)
) PARTITION BY HASH(digest_id);
DO $$
BEGIN
    FOR i IN 0..15 LOOP
        EXECUTE format('CREATE TABLE findings_%s PARTITION OF findings FOR VALUES WITH (MODULUS 16, REMAINDER %s)', i, i);
        EXECUTE format('CREATE TABLE digest_packages_%s PARTITION OF digest_packages FOR VALUES WITH (MODULUS 16, REMAINDER %s)', i, i);
    END LOOP;
END $$;
CREATE INDEX ON findings(advisory_id,digest_id) WHERE resolved_scan_id IS NULL;
CREATE INDEX ON findings(package_id,digest_id) WHERE resolved_scan_id IS NULL;
CREATE FUNCTION ensure_storage_month(month_start date) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    parent text;
    boundary date := date_trunc('month', month_start)::date;
BEGIN
    PERFORM pg_advisory_xact_lock(192387114);
    FOREACH parent IN ARRAY ARRAY['scans','audit_events'] LOOP
        EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
            parent || '_' || to_char(boundary,'YYYYMM'), parent,
            boundary::timestamp AT TIME ZONE 'UTC', (boundary + interval '1 month') AT TIME ZONE 'UTC');
    END LOOP;
END $$;
SELECT ensure_storage_month((now() AT TIME ZONE 'UTC')::date);
SELECT ensure_storage_month(((now() AT TIME ZONE 'UTC') + interval '1 month')::date);
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
    CREATE INDEX advisory_search ON advisories USING gin(external_id gin_trgm_ops);
    CREATE INDEX package_search ON packages USING gin(name gin_trgm_ops);
EXCEPTION WHEN insufficient_privilege OR feature_not_supported OR undefined_file THEN
    RAISE NOTICE 'Optional pg_trgm indexes unavailable';
END $$;
