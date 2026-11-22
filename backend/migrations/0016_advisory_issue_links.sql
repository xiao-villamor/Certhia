CREATE TABLE advisory_issue_links (
    advisory_id integer PRIMARY KEY REFERENCES advisories ON DELETE CASCADE,
    tracker_id uuid REFERENCES issue_trackers ON DELETE SET NULL,
    tracker text NOT NULL,
    issue_url text NOT NULL,
    issue_key text NOT NULL
);
