CREATE TABLE ci_scan_results (
    registry_id uuid NOT NULL REFERENCES registry_profiles ON DELETE CASCADE,
    scan_id uuid NOT NULL REFERENCES scan_directory(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (registry_id, scan_id)
);

CREATE INDEX ON ci_scan_results(scan_id);
