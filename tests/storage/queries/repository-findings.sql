\set repo random(1,:repositories)
SELECT rd.digest_id,f.package_id,f.advisory_id,f.fixed_in
FROM repository_digests rd CROSS JOIN LATERAL (
    SELECT package_id,advisory_id,fixed_in FROM findings
    WHERE digest_id=rd.digest_id AND resolved_scan_id IS NULL
      AND (digest_id,package_id,advisory_id)>(0,0,0)
    ORDER BY package_id,advisory_id LIMIT 51
) f
WHERE rd.repository_id=:repo AND rd.digest_id>=0
ORDER BY rd.digest_id,f.package_id,f.advisory_id LIMIT 51;
