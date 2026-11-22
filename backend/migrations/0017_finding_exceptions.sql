CREATE TABLE finding_exceptions (
    repository_id bigint NOT NULL REFERENCES repositories ON DELETE CASCADE,
    advisory_id integer NOT NULL REFERENCES advisories ON DELETE CASCADE,
    platform text NOT NULL,
    reference text NOT NULL,
    reason text NOT NULL CHECK (length(btrim(reason)) > 0),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (repository_id, advisory_id, platform, reference)
);

-- An empty reference represents all references of the repository on this platform.
CREATE FUNCTION active_finding_exception(repo bigint, advisory integer, target_platform text, target_reference text)
RETURNS TABLE (reference text, reason text, expires_at timestamptz)
LANGUAGE sql STABLE AS $$
    SELECT e.reference, e.reason, e.expires_at
    FROM finding_exceptions e
    WHERE e.repository_id = repo AND e.advisory_id = advisory AND e.platform = target_platform
      AND e.reference IN ('', target_reference) AND e.expires_at > now()
    ORDER BY (e.reference <> '') DESC
    LIMIT 1
$$;
