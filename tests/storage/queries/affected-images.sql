\set advisory random(1,16384)
SELECT page.digest_id,d.digest
FROM (
    SELECT DISTINCT digest_id FROM findings
    WHERE advisory_id=:advisory AND resolved_scan_id IS NULL AND digest_id>0
    ORDER BY digest_id LIMIT 51
) page JOIN digests d ON d.id=page.digest_id
ORDER BY page.digest_id;
