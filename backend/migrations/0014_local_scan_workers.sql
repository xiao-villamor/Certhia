DROP FUNCTION claim_scan(uuid, text[], boolean);

-- Release assigned leases so interrupted scans can be claimed locally.
UPDATE scans s SET status='queued',started_at=NULL
    FROM scan_jobs j JOIN agent_jobs a ON a.lease_id=j.lease_id
    WHERE s.id=j.scan_id AND s.queued_at=j.queued_at;
UPDATE scan_jobs j SET lease_id=NULL,lease_until=NULL,worker=NULL
    FROM agent_jobs a WHERE a.lease_id=j.lease_id;

CREATE FUNCTION claim_scan(owner_id uuid, allowed_sources text[])
RETURNS SETOF scan_jobs LANGUAGE plpgsql AS $$
DECLARE
    job scan_jobs;
BEGIN
    WITH candidate AS (
        SELECT scan_id FROM scan_jobs
        WHERE source=ANY(allowed_sources) AND (lease_until IS NULL OR lease_until <= statement_timestamp())
        ORDER BY priority DESC,queued_at,scan_id LIMIT 1 FOR UPDATE SKIP LOCKED
    ) UPDATE scan_jobs j SET lease_id=gen_random_uuid(),worker=owner_id,
        attempts=attempts+1,lease_until=clock_timestamp()+interval '60 seconds'
        FROM candidate c WHERE j.scan_id=c.scan_id RETURNING j.* INTO job;
    IF NOT FOUND THEN RETURN; END IF;
    UPDATE scans SET status='running',started_at=clock_timestamp() WHERE id=job.scan_id AND queued_at=job.queued_at;
    INSERT INTO scan_activity(scan_id,lease_id,step,title,detail)
        VALUES(job.scan_id,job.lease_id,'started','Preparing scan','A worker claimed the scan.');
    PERFORM pg_notify('certhia_activity',job.scan_id::text);
    RETURN NEXT job;
END $$;

CREATE OR REPLACE FUNCTION finish_scan(job uuid, token uuid, owner_id uuid, failure text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    queued timestamptz;
BEGIN
    DELETE FROM scan_jobs WHERE scan_id=job AND lease_id=token AND worker=owner_id
        AND lease_until>clock_timestamp() RETURNING queued_at INTO queued;
    IF NOT FOUND THEN RAISE EXCEPTION 'Scan lease expired or superseded' USING ERRCODE='P0002'; END IF;
    UPDATE scans SET status=CASE WHEN failure IS NULL THEN 'completed' ELSE 'failed' END,
        error=failure,finished_at=clock_timestamp() WHERE id=job AND queued_at=queued;
    PERFORM pg_notify('certhia_activity',job::text);
END $$;

CREATE OR REPLACE FUNCTION record_scan_progress(job uuid, token uuid, owner_id uuid, stage text, label text, message text)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    PERFORM FROM scan_jobs WHERE scan_id=job AND lease_id=token AND worker=owner_id
        AND lease_until>clock_timestamp() FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    INSERT INTO scan_activity(scan_id,lease_id,step,title,detail) VALUES(job,token,stage,label,message)
        ON CONFLICT(scan_id,lease_id,step) DO NOTHING;
    IF FOUND THEN PERFORM pg_notify('certhia_activity',job::text); END IF;
    RETURN true;
END $$;

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

CREATE OR REPLACE FUNCTION job_claim_wakeup() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('certhia_work','');
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION enqueue_schedule_jobs(run uuid,ids uuid[],images text[],platforms text[],profiles uuid[],sources text[])
RETURNS void LANGUAGE plpgsql AS $$
DECLARE stamp timestamptz := clock_timestamp();
BEGIN
    PERFORM prepare_storage_months(stamp);
    INSERT INTO scan_directory(id,queued_at) SELECT id,stamp FROM unnest(ids) AS id;
    INSERT INTO scans(id,queued_at,reference,platform,status,source,registry_profile_id)
        SELECT id,stamp,image,platform,'queued',source,profile FROM unnest(ids,images,platforms,profiles,sources) AS q(id,image,platform,profile,source);
    INSERT INTO scan_jobs(scan_id,priority,queued_at,source,registry_id,scanners)
        SELECT id,0,stamp,source,profile,'{}' FROM unnest(ids,profiles,sources) AS q(id,profile,source);
    INSERT INTO schedule_run_scans SELECT run,id FROM unnest(ids) AS id;
    PERFORM pg_notify('certhia_work','');
END $$;

CREATE OR REPLACE FUNCTION merge_observations(d bigint, repo bigint, scan bigint, complete_inventory boolean)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    authoritative boolean := current_setting('certhia.partial', true) IS DISTINCT FROM 'on';
BEGIN
    ANALYZE pg_temp.observations;
    INSERT INTO ecosystems(name) SELECT DISTINCT o.ecosystem FROM pg_temp.observations o
        WHERE NOT EXISTS (SELECT FROM ecosystems e WHERE e.name=o.ecosystem) ORDER BY 1
        ON CONFLICT DO NOTHING;
    INSERT INTO packages(ecosystem_id,name,version,purl)
        SELECT DISTINCT e.id,o.name,o.version,o.purl FROM pg_temp.observations o JOIN ecosystems e ON e.name=o.ecosystem
        WHERE NOT EXISTS (SELECT FROM packages p WHERE p.ecosystem_id=e.id AND p.name=o.name
            AND p.version=o.version AND p.purl IS NOT DISTINCT FROM o.purl)
        ORDER BY 1,2,3,4 ON CONFLICT DO NOTHING;
    CREATE TEMP TABLE matched ON COMMIT DROP AS
        SELECT DISTINCT p.id AS package_id,o.external_id,o.severity,o.fixed,o.title,o.layer_index
        FROM pg_temp.observations o JOIN ecosystems e ON o.ecosystem=e.name
        JOIN packages p ON p.ecosystem_id=e.id AND p.name=o.name AND p.version=o.version AND p.purl IS NOT DISTINCT FROM o.purl;
    ANALYZE matched;
    IF complete_inventory AND NOT (SELECT inventory_complete FROM digests WHERE id=d) THEN
        INSERT INTO digest_packages(digest_id,package_id,layer_index) SELECT DISTINCT d,package_id,layer_index FROM matched WHERE external_id IS NULL;
        UPDATE digests SET inventory_complete=true WHERE id=d;
    END IF;
    CREATE TEMP TABLE incoming_advisories ON COMMIT DROP AS
        SELECT DISTINCT ON(m.external_id) m.external_id,s.id AS severity_id,m.title
        FROM matched m JOIN severities s ON s.name=lower(m.severity)
        WHERE m.external_id IS NOT NULL ORDER BY m.external_id,s.id DESC,m.title;
    ANALYZE incoming_advisories;
    -- Include every digest whose cached severity distribution can change.
    CREATE TEMP TABLE recount(id bigint PRIMARY KEY) ON COMMIT DROP;
    INSERT INTO recount VALUES(d);
    INSERT INTO recount SELECT DISTINCT f.digest_id FROM incoming_advisories i
        JOIN advisories a ON a.external_id=i.external_id AND a.source='trivy' AND a.severity_id<>i.severity_id
        JOIN findings f ON f.advisory_id=a.id AND f.resolved_scan_id IS NULL ON CONFLICT DO NOTHING;
    ANALYZE recount;
    CREATE TEMP TABLE old_digest_counts ON COMMIT DROP AS
        SELECT c.* FROM digest_severity_counts c JOIN recount r ON c.digest_id=r.id;
    INSERT INTO advisories(external_id,source,severity_id,summary)
        SELECT i.external_id,'trivy',i.severity_id,i.title FROM incoming_advisories i
        LEFT JOIN advisories a ON a.external_id=i.external_id AND a.source='trivy'
        WHERE a.id IS NULL OR (a.severity_id,a.summary) IS DISTINCT FROM (i.severity_id,i.title)
        ORDER BY i.external_id
        ON CONFLICT(external_id,source) DO UPDATE SET severity_id=excluded.severity_id,summary=excluded.summary
        WHERE (advisories.severity_id,advisories.summary) IS DISTINCT FROM (excluded.severity_id,excluded.summary);
    INSERT INTO fix_versions(version) SELECT DISTINCT fixed FROM matched m WHERE fixed<>''
        AND NOT EXISTS(SELECT FROM fix_versions v WHERE v.version=m.fixed) ORDER BY 1 ON CONFLICT DO NOTHING;
    CREATE TEMP TABLE observed ON COMMIT DROP AS
        SELECT DISTINCT ON (m.package_id,a.id) m.package_id,a.id AS advisory_id,v.id AS fixed_in
        FROM matched m JOIN advisories a ON a.external_id=m.external_id AND a.source='trivy'
        LEFT JOIN fix_versions v ON v.version=m.fixed ORDER BY m.package_id,a.id,m.fixed DESC;
    ALTER TABLE observed ADD PRIMARY KEY(package_id,advisory_id);
    ANALYZE observed;
    CREATE TEMP TABLE previous ON COMMIT DROP AS SELECT package_id,advisory_id FROM findings
        WHERE digest_id=d AND resolved_scan_id IS NULL;
    ANALYZE previous;
    INSERT INTO finding_transitions
        SELECT scan,d,package_id,advisory_id,p.package_id IS NULL FROM previous p FULL JOIN observed o USING(package_id,advisory_id)
        WHERE (authoritative AND o.package_id IS NULL) OR p.package_id IS NULL;
    UPDATE findings f SET resolved_scan_id=scan FROM finding_transitions t WHERE t.scan_no=scan AND NOT t.opened
        AND f.digest_id=d AND f.advisory_id=t.advisory_id AND f.package_id=t.package_id;
    INSERT INTO findings(digest_id,package_id,advisory_id,fixed_in,first_seen_scan_id,last_seen_scan_id)
        SELECT d,package_id,advisory_id,fixed_in,scan,scan FROM observed
        ON CONFLICT(digest_id,package_id,advisory_id) DO UPDATE SET last_seen_scan_id=scan,
            fixed_in=excluded.fixed_in,resolved_scan_id=NULL;

    -- Apply signed deltas to existing rows before inserting previously unseen keys.
    CREATE TEMP TABLE package_delta ON COMMIT DROP AS
        SELECT package_id,sum(CASE WHEN opened THEN 1 ELSE -1 END) AS delta
        FROM finding_transitions WHERE scan_no=scan GROUP BY package_id;
    INSERT INTO package_counts SELECT package_id,0 FROM package_delta ORDER BY package_id ON CONFLICT DO NOTHING;
    UPDATE package_counts c SET total=c.total+p.delta FROM package_delta p WHERE c.package_id=p.package_id;
    CREATE TEMP TABLE advisory_delta ON COMMIT DROP AS
        SELECT advisory_id, CASE WHEN p.advisory_id IS NULL THEN 1 ELSE -1 END AS delta
        FROM (SELECT DISTINCT advisory_id FROM previous) p FULL JOIN (SELECT DISTINCT advisory_id FROM observed) o USING(advisory_id)
        WHERE p.advisory_id IS NULL OR (authoritative AND o.advisory_id IS NULL);
    INSERT INTO advisory_counts SELECT advisory_id,0 FROM advisory_delta ORDER BY advisory_id ON CONFLICT DO NOTHING;
    UPDATE advisory_counts c SET affected_images=c.affected_images+a.delta FROM advisory_delta a WHERE c.advisory_id=a.advisory_id;

    DELETE FROM digest_severity_counts c USING recount r WHERE c.digest_id=r.id;
    INSERT INTO digest_severity_counts SELECT f.digest_id,a.severity_id,count(*) FROM recount r
        JOIN findings f ON f.digest_id=r.id AND f.resolved_scan_id IS NULL JOIN advisories a ON a.id=f.advisory_id
        GROUP BY f.digest_id,a.severity_id;
    CREATE TEMP TABLE repo_delta ON COMMIT DROP AS
        SELECT rd.repository_id,c.severity_id,sum(c.total) AS delta FROM repository_digests rd JOIN (
            SELECT c.* FROM digest_severity_counts c JOIN recount r ON r.id=c.digest_id
            UNION ALL SELECT digest_id,severity_id,-total FROM old_digest_counts
        ) c USING(digest_id) GROUP BY rd.repository_id,c.severity_id;
    IF NOT EXISTS(SELECT FROM repository_digests WHERE digest_id=d AND repository_id=repo) THEN
        INSERT INTO repository_digests VALUES(repo,d);
        INSERT INTO repo_delta SELECT repo,severity_id,total FROM digest_severity_counts WHERE digest_id=d;
    END IF;
    INSERT INTO repository_severity_counts SELECT DISTINCT repository_id,severity_id,0 FROM repo_delta
        ORDER BY 1,2 ON CONFLICT DO NOTHING;
    UPDATE repository_severity_counts c SET total=c.total+r.delta FROM
        (SELECT repository_id,severity_id,sum(delta) delta FROM repo_delta GROUP BY repository_id,severity_id) r
        WHERE c.repository_id=r.repository_id AND c.severity_id=r.severity_id;
END $$;

DROP TABLE agent_jobs;
DROP TABLE agents;
