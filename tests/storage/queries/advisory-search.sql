\set suffix random(100,999)
SELECT id,external_id,summary FROM advisories
WHERE external_id ILIKE '%'||:suffix::text||'%' ORDER BY external_id,id LIMIT 51;
