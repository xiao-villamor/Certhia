CREATE TABLE image_finding_tracking (
    repository_id bigint NOT NULL,
    digest_id bigint NOT NULL,
    reference text NOT NULL,
    platform text NOT NULL,
    advisory_id integer NOT NULL REFERENCES advisories,
    status text NOT NULL,
    note text NOT NULL,
    updated_at timestamptz NOT NULL,
    tracker_id uuid REFERENCES issue_trackers ON DELETE SET NULL,
    tracker text,
    issue_url text,
    issue_key text,
    PRIMARY KEY (repository_id,digest_id,reference,platform,advisory_id),
    FOREIGN KEY (repository_id,digest_id) REFERENCES repository_digests,
    CHECK ((tracker IS NULL AND issue_url IS NULL AND issue_key IS NULL AND tracker_id IS NULL)
        OR (tracker IS NOT NULL AND issue_url IS NOT NULL AND issue_key IS NOT NULL))
);

-- A repository ticket used to cover any affected version in the repository.
-- Carry it forward for versions with saved evidence at upgrade time.
WITH affected_versions AS (
    SELECT DISTINCT s.repository_id,s.digest_id,s.reference,s.platform,t.advisory_id
    FROM triage t
    JOIN scans s ON s.repository_id=t.repository_id AND s.status='completed'
    JOIN scan_directory d USING (id,queued_at)
    WHERE EXISTS (
        SELECT FROM scan_finding_keys(s.digest_id,d.observed_order) k
        WHERE k.advisory_id=t.advisory_id
    )
)
INSERT INTO image_finding_tracking
    (repository_id,digest_id,reference,platform,advisory_id,status,note,updated_at,tracker_id,tracker,issue_url,issue_key)
SELECT v.repository_id,v.digest_id,v.reference,v.platform,v.advisory_id,t.status,t.note,t.updated_at,
       l.tracker_id,l.tracker,l.url,l.issue_key
FROM affected_versions v
JOIN triage t USING (repository_id,advisory_id)
LEFT JOIN issue_links l USING (repository_id,advisory_id);
