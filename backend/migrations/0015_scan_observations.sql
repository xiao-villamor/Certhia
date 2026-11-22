-- NULL marks scans recorded before exact per-scan observations were stored.
ALTER TABLE scans ADD COLUMN observation_complete boolean;

CREATE TABLE scan_observed_findings (
    scan_no bigint NOT NULL REFERENCES scan_directory ON DELETE CASCADE,
    package_id integer NOT NULL REFERENCES packages,
    advisory_id integer NOT NULL REFERENCES advisories,
    fixed_in integer REFERENCES fix_versions,
    severity_id smallint NOT NULL REFERENCES severities,
    title text,
    PRIMARY KEY (scan_no, package_id, advisory_id)
);

CREATE FUNCTION observed_findings(manifest bigint, observation bigint, scan bigint, exact boolean)
RETURNS TABLE(package_id integer, advisory_id integer, fixed_in integer, severity_id smallint, title text)
LANGUAGE sql STABLE AS $$
    SELECT o.package_id,o.advisory_id,o.fixed_in,o.severity_id,o.title
    FROM scan_observed_findings o WHERE exact AND o.scan_no=scan
    UNION ALL
    SELECT k.package_id,k.advisory_id,f.fixed_in,a.severity_id,a.summary
    FROM scan_finding_keys(manifest,observation) k
    JOIN findings f ON (f.digest_id,f.package_id,f.advisory_id)=(manifest,k.package_id,k.advisory_id)
    JOIN advisories a ON a.id=k.advisory_id
    WHERE NOT exact
$$;

CREATE VIEW latest_completed_scans AS
SELECT DISTINCT ON (s.reference,s.platform) s.*
FROM scans s WHERE s.status='completed'
ORDER BY s.reference,s.platform,s.finished_at DESC NULLS LAST,s.id DESC;

CREATE TABLE patch_publications (
    id uuid PRIMARY KEY,
    patch_id uuid NOT NULL REFERENCES patches ON DELETE CASCADE,
    reference text NOT NULL,
    pinned_reference text,
    registry_id uuid REFERENCES registry_profiles ON DELETE SET NULL,
    used_registry boolean NOT NULL,
    scan_id uuid REFERENCES scan_directory(id) ON DELETE SET NULL,
    published_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX patch_publications_history ON patch_publications(patch_id,id DESC);
CREATE UNIQUE INDEX patch_publications_scan ON patch_publications(scan_id) WHERE scan_id IS NOT NULL;
