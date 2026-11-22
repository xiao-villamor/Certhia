SELECT p.name,p.version,c.package_id,c.total
FROM package_counts c JOIN packages p ON p.id=c.package_id
ORDER BY c.total DESC,c.package_id LIMIT 51;
