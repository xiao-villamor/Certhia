CREATE FUNCTION enqueue_schedule_jobs(run uuid,ids uuid[],images text[],platforms text[],profiles uuid[],sources text[])
RETURNS void LANGUAGE plpgsql AS $$
DECLARE stamp timestamptz := clock_timestamp();
BEGIN
    PERFORM prepare_storage_months(stamp);
    INSERT INTO scan_directory(id,queued_at) SELECT id,stamp FROM unnest(ids) AS id;
    INSERT INTO scans(id,queued_at,reference,platform,status,source,registry_profile_id)
        SELECT id,stamp,image,platform,'queued',source,profile FROM unnest(ids,images,platforms,profiles,sources) AS q(id,image,platform,profile,source);
    INSERT INTO scan_jobs(scan_id,priority,queued_at,source,registry_id,scanners)
        SELECT id,0,stamp,source,profile,'{}' FROM unnest(ids,profiles,sources) AS q(id,profile,source);
    INSERT INTO schedule_run_scans SELECT run,id FROM unnest(ids) AS id;
    PERFORM pg_notify('certhia_work','');
END $$;
