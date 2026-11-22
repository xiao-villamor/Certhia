CREATE TABLE stored_blobs(object_key text PRIMARY KEY,touched_at timestamptz NOT NULL);
CREATE INDEX stored_blobs_age ON stored_blobs(touched_at,object_key);
CREATE INDEX scan_evidence ON scans(raw_report_ref) WHERE raw_report_ref IS NOT NULL;
CREATE INDEX artifact_evidence ON artifact_refs(object_key) WHERE owned;
INSERT INTO stored_blobs SELECT raw_report_ref,now() FROM scans WHERE raw_report_ref IS NOT NULL
    UNION SELECT object_key,now() FROM artifact_refs WHERE owned;
