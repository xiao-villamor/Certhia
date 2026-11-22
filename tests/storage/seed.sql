-- Run using psql against a fresh migrated database. Override -v repositories=N
-- for a smaller run. Committed batches remain available for diagnosis on error.
\set ON_ERROR_STOP on
\if :{?repositories}
\else
\set repositories 5000
\endif
SELECT set_config('certhia.seed_repositories', :'repositories', false);
CREATE PROCEDURE pg_temp.seed_certhia() LANGUAGE plpgsql AS $$
DECLARE
    repos integer := current_setting('certhia.seed_repositories')::integer;
    first_digest integer := 1;
    last_digest integer;
    registry uuid := gen_random_uuid();
    stamp timestamptz := now();
    uuid_prefix text := lpad(to_hex((extract(epoch FROM stamp)*1000)::bigint),12,'0') || '70008000';
BEGIN
    IF repos NOT BETWEEN 1 AND 50000 THEN RAISE EXCEPTION 'Choose 1 to 50000 repositories'; END IF;
    IF EXISTS(SELECT FROM digests) OR EXISTS(SELECT FROM packages) OR EXISTS(SELECT FROM repositories)
        OR EXISTS(SELECT FROM scan_directory) OR EXISTS(SELECT FROM advisories) OR EXISTS(SELECT FROM ecosystems)
        THEN RAISE EXCEPTION 'Seeding requires an empty disposable database'; END IF;
    PERFORM prepare_storage_months(stamp);
    INSERT INTO registries(id,name,host) VALUES(registry,'Seed registry','registry.fixture.test');
    INSERT INTO ecosystems(name) VALUES('apk');
    INSERT INTO repositories(id,registry_id,name) OVERRIDING SYSTEM VALUE
        SELECT i,registry,'team-'||(i%100)||'/service-'||i FROM generate_series(1,repos) i;
    INSERT INTO packages(id,ecosystem_id,name,version,purl) OVERRIDING SYSTEM VALUE
        SELECT i,e.id,'pkg-'||(i%8192), (i/8192)||'.1','pkg:apk/pkg-'||(i%8192)||'@'||(i/8192)||'.1'
        FROM generate_series(1,65536) i CROSS JOIN ecosystems e;
    INSERT INTO advisories(id,external_id,source,severity_id,summary) OVERRIDING SYSTEM VALUE
        SELECT i,'CVE-2025-'||lpad(i::text,5,'0'),'trivy',(i%5)::smallint,'Fixture advisory '||i
        FROM generate_series(1,16384) i;
    COMMIT;
    WHILE first_digest<=repos*50 LOOP
        last_digest := least(first_digest+249,repos*50);
        INSERT INTO digests(id,digest,os,arch,size,first_scanned_at,inventory_complete) OVERRIDING SYSTEM VALUE
            SELECT i,'sha256:'||encode(sha256(i::text::bytea),'hex'),'alpine','amd64',12000000+(i%9000)*1024,stamp,true
            FROM generate_series(first_digest,last_digest) i;
        INSERT INTO repository_digests SELECT ((i-1)/50)+1,i FROM generate_series(first_digest,last_digest) i;
        INSERT INTO image_tags SELECT ((i-1)/50)+1,'v'||((i-1)%50),'linux/amd64',i,stamp
            FROM generate_series(first_digest,last_digest) i;
        INSERT INTO scan_directory(scan_no,id,queued_at,observed_order) OVERRIDING SYSTEM VALUE
            SELECT i,(uuid_prefix||lpad(to_hex(i),12,'0'))::uuid,stamp,i FROM generate_series(first_digest,last_digest) i;
        INSERT INTO scans(id,queued_at,repository_id,digest_id,reference,platform,scanner,status,started_at,finished_at)
            SELECT s.id,stamp,r.id,i,'registry.fixture.test/'||r.name||':v'||((i-1)%50),
                'linux/amd64','trivy','completed',stamp,stamp
            FROM generate_series(first_digest,last_digest) i JOIN repositories r ON r.id=(i-1)/50+1
            JOIN scan_directory s ON s.scan_no=i;
        -- 200 shared base packages plus 200 rotating application dependencies.
        INSERT INTO digest_packages(digest_id,package_id)
            SELECT i,CASE WHEN k<=200 THEN k ELSE 201+((i*37+k)%65336) END
            FROM generate_series(first_digest,last_digest) i CROSS JOIN generate_series(1,400) k;
        INSERT INTO findings(digest_id,package_id,advisory_id,first_seen_scan_id,last_seen_scan_id)
            SELECT digest_id,package_id,1+(package_id%16384),digest_id,digest_id
            FROM digest_packages WHERE digest_id BETWEEN first_digest AND last_digest
            UNION ALL SELECT i,1,16384,i,i FROM generate_series(first_digest,last_digest) i;
        first_digest := last_digest+1;
        COMMIT;
    END LOOP;
    INSERT INTO digest_severity_counts SELECT f.digest_id,a.severity_id,count(*) FROM findings f
        JOIN advisories a ON a.id=f.advisory_id GROUP BY f.digest_id,a.severity_id;
    INSERT INTO repository_severity_counts SELECT r.repository_id,c.severity_id,sum(c.total)
        FROM digest_severity_counts c JOIN repository_digests r USING(digest_id) GROUP BY r.repository_id,c.severity_id;
    INSERT INTO package_counts SELECT package_id,count(*) FROM findings GROUP BY package_id;
    INSERT INTO advisory_counts SELECT advisory_id,count(DISTINCT digest_id) FROM findings GROUP BY advisory_id;
    PERFORM setval('observation_order',repos*50);
    PERFORM setval(pg_get_serial_sequence('digests','id'),repos*50);
    PERFORM setval(pg_get_serial_sequence('repositories','id'),repos);
    PERFORM setval(pg_get_serial_sequence('scan_directory','scan_no'),repos*50);
    PERFORM setval(pg_get_serial_sequence('packages','id'),65536);
    PERFORM setval(pg_get_serial_sequence('advisories','id'),16384);
END $$;
CALL pg_temp.seed_certhia();
ANALYZE;
