ALTER TABLE scans
    ADD COLUMN source text NOT NULL DEFAULT 'import',
    ADD COLUMN registry_profile_id uuid REFERENCES registry_profiles ON DELETE SET NULL,
    ADD COLUMN scanners text[] NOT NULL DEFAULT '{}',
    ADD COLUMN counts jsonb,
    ADD COLUMN inventory_available boolean NOT NULL DEFAULT false;
CREATE TABLE scan_checks(
    scan_id uuid REFERENCES scan_directory(id), ordinal integer,
    category text NOT NULL,external_id text NOT NULL,target text NOT NULL,severity text NOT NULL,title text NOT NULL,
    detail text NOT NULL,PRIMARY KEY(scan_id,ordinal)
);
CREATE INDEX scans_reference_time ON scans(reference,platform,finished_at DESC,id DESC);
CREATE INDEX finding_history ON finding_transitions(digest_id,package_id,advisory_id,scan_no DESC);

CREATE OR REPLACE FUNCTION enqueue_scan(job uuid, image text, platform_name text, origin text, registry uuid,
                            engines text[], weight integer) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    queued timestamptz := clock_timestamp();
BEGIN
    PERFORM prepare_storage_months(queued);
    INSERT INTO scan_directory(id,queued_at) VALUES(job,queued);
    INSERT INTO scans(id,queued_at,reference,platform,status,priority,source,registry_profile_id,scanners)
        VALUES(job,queued,image,platform_name,'queued',weight,origin,registry,engines);
    INSERT INTO scan_jobs(scan_id,priority,queued_at,source,registry_id,scanners)
        VALUES(job,weight,queued,origin,registry,engines);
    PERFORM pg_notify('certhia_work','');
    PERFORM pg_notify('certhia_activity',job::text);
END $$;

CREATE SEQUENCE observation_order;
ALTER TABLE scan_directory ADD COLUMN observed_order bigint;
UPDATE scan_directory SET observed_order=scan_no;
SELECT setval('observation_order',greatest(1,coalesce(max(observed_order),0)+1),false) FROM scan_directory;
CREATE OR REPLACE FUNCTION scan_finding_keys(manifest bigint, observation bigint) RETURNS TABLE(package_id integer,advisory_id integer)
LANGUAGE sql STABLE AS $$
    SELECT f.package_id,f.advisory_id FROM findings f JOIN scan_directory first_scan ON first_scan.scan_no=f.first_seen_scan_id
    LEFT JOIN LATERAL (
        SELECT t.opened FROM finding_transitions t JOIN scan_directory sd ON sd.scan_no=t.scan_no
        WHERE (t.digest_id,t.package_id,t.advisory_id)=(f.digest_id,f.package_id,f.advisory_id)
            AND sd.observed_order<=observation
        ORDER BY sd.observed_order DESC LIMIT 1
    ) change ON true
    WHERE f.digest_id=manifest AND first_scan.observed_order<=observation AND coalesce(change.opened,true)
$$;
CREATE FUNCTION job_claim_wakeup() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('certhia_work','');
    RETURN NULL;
END $$;
CREATE TRIGGER job_claim_wakeup AFTER UPDATE OF lease_id ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION job_claim_wakeup();

CREATE INDEX scan_digest_reference ON scans(repository_id,digest_id,finished_at DESC,id DESC) WHERE status='completed';
CREATE INDEX scans_history_id ON scans(id DESC);
CREATE INDEX scan_job_source_expiry ON scan_jobs(source,lease_until);
