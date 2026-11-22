CREATE TABLE settings (key text PRIMARY KEY,value jsonb NOT NULL);
CREATE TABLE notification_config (singleton boolean PRIMARY KEY CHECK(singleton), secret bytea NOT NULL);
CREATE TABLE registry_config (
    registry_id uuid PRIMARY KEY REFERENCES registries ON DELETE CASCADE, provider text NOT NULL, auth_host text,
    auto_sync boolean NOT NULL DEFAULT false, protocol text NOT NULL DEFAULT 'https',skip_tls boolean NOT NULL DEFAULT false,namespace text
);
CREATE TABLE registry_catalog (
    registry_id uuid PRIMARY KEY REFERENCES registries ON DELETE CASCADE,refreshed_at timestamptz,error text
);
CREATE TABLE registry_catalog_entries (
    registry_id uuid REFERENCES registry_catalog ON DELETE CASCADE, repository text, tag text, PRIMARY KEY(registry_id,repository,tag)
);
CREATE TABLE registry_webhooks (
    registry_id uuid PRIMARY KEY REFERENCES registries ON DELETE CASCADE,token_hash bytea NOT NULL,created_at timestamptz NOT NULL
);
CREATE TABLE triage (
    repository_id bigint REFERENCES repositories, advisory_id integer REFERENCES advisories,status text NOT NULL,note text NOT NULL,
    updated_by text,updated_at timestamptz NOT NULL,PRIMARY KEY(repository_id,advisory_id)
);
CREATE TABLE issue_trackers (
    id uuid PRIMARY KEY,name text NOT NULL,provider text NOT NULL,url_template text NOT NULL
);
CREATE TABLE issue_links (
    repository_id bigint,advisory_id integer,tracker_id uuid REFERENCES issue_trackers ON DELETE SET NULL,
    tracker text NOT NULL,url text NOT NULL,issue_key text NOT NULL,PRIMARY KEY(repository_id,advisory_id),
    FOREIGN KEY(repository_id,advisory_id) REFERENCES triage ON DELETE CASCADE
);
CREATE TABLE vex_reviews (
    scan_id uuid REFERENCES scan_directory(id),advisory_id integer REFERENCES advisories,
    status text NOT NULL,note text NOT NULL,reviewed_at timestamptz NOT NULL,PRIMARY KEY(scan_id,advisory_id)
);
CREATE TABLE batches(id uuid PRIMARY KEY,created_at timestamptz NOT NULL);
CREATE TABLE batch_scans(batch_id uuid REFERENCES batches ON DELETE CASCADE,scan_id uuid REFERENCES scan_directory(id),PRIMARY KEY(batch_id,scan_id));
CREATE TABLE image_watches (
    id uuid PRIMARY KEY,reference text NOT NULL,platform text NOT NULL,created_at timestamptz NOT NULL,UNIQUE(reference,platform)
);
CREATE TABLE watch_seen (
    watch_id uuid REFERENCES image_watches ON DELETE CASCADE,advisory_id integer REFERENCES advisories,PRIMARY KEY(watch_id,advisory_id)
);
CREATE TABLE watch_alerts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,watch_id uuid NOT NULL REFERENCES image_watches ON DELETE CASCADE,
    scan_id uuid NOT NULL REFERENCES scan_directory(id),created_at timestamptz NOT NULL DEFAULT now(),
    next_attempt timestamptz,delivered_at timestamptz,attempts integer NOT NULL DEFAULT 0,error text
);
CREATE INDEX ON watch_alerts(next_attempt,id) WHERE next_attempt IS NOT NULL;
CREATE TABLE watch_alert_advisories (
    alert_id bigint REFERENCES watch_alerts ON DELETE CASCADE,advisory_id integer REFERENCES advisories,PRIMARY KEY(alert_id,advisory_id)
);
CREATE TABLE artifact_refs (
    scan_id uuid REFERENCES scan_directory(id),kind text,object_key text NOT NULL,owned boolean NOT NULL,PRIMARY KEY(scan_id,kind)
);
CREATE TABLE patches (
    id uuid PRIMARY KEY,scan_id uuid NOT NULL REFERENCES scan_directory(id),reference text NOT NULL,platform text NOT NULL,
    status text NOT NULL,created_at timestamptz NOT NULL,finished_at timestamptz,error text,packages jsonb NOT NULL
);

CREATE FUNCTION retain_storage(scan_days integer,audit_days integer) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    part record;
    pending boolean;
    month_end date;
BEGIN
    IF scan_days NOT BETWEEN 1 AND 365 OR audit_days NOT BETWEEN 1 AND 365 THEN
        RAISE EXCEPTION 'Invalid retention period';
    END IF;
    IF NOT pg_try_advisory_xact_lock(192387114) THEN RETURN; END IF;
    PERFORM prepare_storage_months(now());
    FOR part IN SELECT inhparent AS parent,inhrelid::regclass AS relation,c.relname AS name
        FROM pg_inherits JOIN pg_class c ON c.oid=inhrelid
        WHERE inhparent IN ('scans'::regclass,'audit_events'::regclass) LOOP
        IF part.name !~ '^(scans|audit_events)_[0-9]{6}$' THEN CONTINUE; END IF;
        month_end := to_date(right(part.name,6),'YYYYMM') + interval '1 month';
        IF month_end > (now() AT TIME ZONE 'UTC')::date -
            (CASE WHEN part.parent='scans'::regclass THEN scan_days ELSE audit_days END) THEN CONTINUE; END IF;
        IF part.parent='scans'::regclass THEN
            EXECUTE format('LOCK TABLE %s IN ACCESS EXCLUSIVE MODE',part.relation);
            EXECUTE format('SELECT EXISTS(SELECT FROM %s WHERE status IN (''queued'',''running''))',part.relation) INTO pending;
            IF pending THEN CONTINUE; END IF;
        END IF;
        EXECUTE format('DROP TABLE %s',part.relation);
    END LOOP;
END $$;
