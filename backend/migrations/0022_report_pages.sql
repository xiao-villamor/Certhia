CREATE TABLE report_evidence_index (
    scan_id uuid PRIMARY KEY REFERENCES scan_directory(id) ON DELETE CASCADE
);

CREATE TABLE report_finding_evidence (
    scan_id uuid NOT NULL REFERENCES report_evidence_index(scan_id) ON DELETE CASCADE,
    package_id integer NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    advisory text NOT NULL,
    aliases text[] NOT NULL,
    scanners text[] NOT NULL,
    PRIMARY KEY (scan_id, package_id, advisory)
);

CREATE TABLE report_discrepancy_index (
    scan_id uuid PRIMARY KEY REFERENCES scan_directory(id) ON DELETE CASCADE,
    summary jsonb NOT NULL
);

CREATE TABLE report_discrepancy_entries (
    scan_id uuid NOT NULL REFERENCES report_discrepancy_index(scan_id) ON DELETE CASCADE,
    reconciled boolean NOT NULL,
    ordinal bigint NOT NULL,
    entry jsonb NOT NULL,
    search_text text NOT NULL,
    PRIMARY KEY (scan_id, reconciled, ordinal)
);

CREATE INDEX scans_completed_repository_version ON scans
    (repository_id, platform, finished_at DESC, id DESC) WHERE status='completed';
