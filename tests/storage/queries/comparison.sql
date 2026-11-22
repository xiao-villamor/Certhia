\set digest random(1,:repositories * 50 - 1)
WITH baseline AS (
    SELECT package_id,advisory_id FROM findings WHERE digest_id=:digest AND resolved_scan_id IS NULL
), target AS (
    SELECT package_id,advisory_id FROM findings WHERE digest_id=:digest+1 AND resolved_scan_id IS NULL
)
SELECT package_id,advisory_id,(b.package_id IS NULL) AS added
FROM baseline b FULL JOIN target t USING(package_id,advisory_id)
WHERE b.package_id IS NULL OR t.package_id IS NULL
ORDER BY package_id,advisory_id LIMIT 51;
