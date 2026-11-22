CREATE TABLE digest_severity_counts (
    digest_id bigint REFERENCES digests, severity_id smallint REFERENCES severities,
    total bigint NOT NULL CHECK(total >= 0), PRIMARY KEY(digest_id,severity_id)
);
CREATE TABLE repository_severity_counts (
    repository_id bigint REFERENCES repositories, severity_id smallint REFERENCES severities,
    total bigint NOT NULL CHECK(total >= 0), PRIMARY KEY(repository_id,severity_id)
);
CREATE TABLE package_counts (
    package_id integer PRIMARY KEY REFERENCES packages, total bigint NOT NULL CHECK(total >= 0)
);
CREATE INDEX ON package_counts(total DESC,package_id);
CREATE TABLE advisory_counts (
    advisory_id integer PRIMARY KEY REFERENCES advisories, affected_images bigint NOT NULL CHECK(affected_images >= 0)
);
CREATE TABLE finding_transitions (
    scan_no bigint REFERENCES scan_directory, digest_id bigint NOT NULL, package_id integer NOT NULL,
    advisory_id integer NOT NULL, opened boolean NOT NULL,
    PRIMARY KEY(scan_no,digest_id,package_id,advisory_id)
);

-- The caller serializes observations for this digest and retries serialization failures.
-- pg_temp.observations holds deduplicated input from a binary COPY.
CREATE FUNCTION merge_observations(d bigint, repo bigint, scan bigint, complete_inventory boolean)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO ecosystems(name) SELECT DISTINCT ecosystem FROM pg_temp.observations ORDER BY 1
        ON CONFLICT DO NOTHING;
    INSERT INTO packages(ecosystem_id,name,version)
        SELECT DISTINCT e.id,o.name,o.version FROM pg_temp.observations o JOIN ecosystems e ON e.name=o.ecosystem
        ORDER BY 1,2,3 ON CONFLICT DO NOTHING;
    CREATE TEMP TABLE matched ON COMMIT DROP AS
        SELECT DISTINCT p.id AS package_id,o.external_id,o.severity,o.fixed,o.title
        FROM pg_temp.observations o JOIN ecosystems e ON o.ecosystem=e.name
        JOIN packages p ON p.ecosystem_id=e.id AND p.name=o.name AND p.version=o.version AND p.purl IS NULL;
    IF complete_inventory AND NOT (SELECT inventory_complete FROM digests WHERE id=d) THEN
        INSERT INTO digest_packages(digest_id,package_id) SELECT DISTINCT d,package_id FROM matched;
        UPDATE digests SET inventory_complete=true WHERE id=d;
    END IF;
    CREATE TEMP TABLE incoming_advisories ON COMMIT DROP AS
        SELECT DISTINCT ON(m.external_id) m.external_id,s.id AS severity_id,m.title
        FROM matched m JOIN severities s ON s.name=lower(m.severity)
        WHERE m.external_id IS NOT NULL ORDER BY m.external_id,s.id DESC,m.title;
    -- Include every digest whose cached severity distribution can change.
    CREATE TEMP TABLE recount(id bigint PRIMARY KEY) ON COMMIT DROP;
    INSERT INTO recount VALUES(d);
    INSERT INTO recount SELECT DISTINCT f.digest_id FROM incoming_advisories i
        JOIN advisories a ON a.external_id=i.external_id AND a.source='trivy' AND a.severity_id<>i.severity_id
        JOIN findings f ON f.advisory_id=a.id AND f.resolved_scan_id IS NULL ON CONFLICT DO NOTHING;
    CREATE TEMP TABLE old_digest_counts ON COMMIT DROP AS
        SELECT c.* FROM digest_severity_counts c JOIN recount r ON c.digest_id=r.id;
    INSERT INTO advisories(external_id,source,severity_id,summary)
        SELECT external_id,'trivy',severity_id,title FROM incoming_advisories ORDER BY external_id
        ON CONFLICT(external_id,source) DO UPDATE SET severity_id=excluded.severity_id,summary=excluded.summary
        WHERE (advisories.severity_id,advisories.summary) IS DISTINCT FROM (excluded.severity_id,excluded.summary);
    INSERT INTO fix_versions(version) SELECT DISTINCT fixed FROM matched WHERE fixed<>'' ORDER BY 1 ON CONFLICT DO NOTHING;
    CREATE TEMP TABLE observed ON COMMIT DROP AS
        SELECT DISTINCT ON (m.package_id,a.id) m.package_id,a.id AS advisory_id,v.id AS fixed_in
        FROM matched m JOIN advisories a ON a.external_id=m.external_id AND a.source='trivy'
        LEFT JOIN fix_versions v ON v.version=m.fixed ORDER BY m.package_id,a.id,m.fixed DESC;
    ALTER TABLE observed ADD PRIMARY KEY(package_id,advisory_id);
    CREATE TEMP TABLE previous ON COMMIT DROP AS SELECT package_id,advisory_id FROM findings
        WHERE digest_id=d AND resolved_scan_id IS NULL;
    INSERT INTO finding_transitions
        SELECT scan,d,package_id,advisory_id,p.package_id IS NULL FROM previous p FULL JOIN observed o USING(package_id,advisory_id)
        WHERE o.package_id IS NULL OR p.package_id IS NULL;
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
        WHERE p.advisory_id IS NULL OR o.advisory_id IS NULL;
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

-- Fast path avoids taking the DDL lock in ordinary insert transactions.
CREATE FUNCTION prepare_storage_months(at_time timestamptz) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    boundary date := date_trunc('month', at_time AT TIME ZONE 'UTC')::date;
BEGIN
    FOR i IN 0..1 LOOP
        IF to_regclass('scans_' || to_char(boundary,'YYYYMM')) IS NULL
            OR to_regclass('audit_events_' || to_char(boundary,'YYYYMM')) IS NULL THEN
            PERFORM ensure_storage_month(boundary);
        END IF;
        boundary := boundary + interval '1 month';
    END LOOP;
END $$;
