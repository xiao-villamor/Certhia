CREATE TABLE scan_jobs (
    scan_id uuid PRIMARY KEY REFERENCES scan_directory(id), priority integer NOT NULL,
    queued_at timestamptz NOT NULL, source text NOT NULL, registry_id uuid REFERENCES registries,
    scanners text[] NOT NULL, lease_id uuid UNIQUE, lease_until timestamptz, worker uuid,
    attempts integer NOT NULL DEFAULT 0,
    CHECK((lease_id IS NULL) = (lease_until IS NULL) AND (lease_id IS NULL) = (worker IS NULL))
);
CREATE INDEX scan_jobs_waiting ON scan_jobs(priority DESC, queued_at,scan_id) WHERE lease_id IS NULL;
CREATE INDEX scan_jobs_expiry ON scan_jobs(lease_until) WHERE lease_id IS NOT NULL;
CREATE TABLE scan_activity (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,scan_id uuid NOT NULL REFERENCES scan_directory(id),
    lease_id uuid, step text NOT NULL,title text NOT NULL,detail text NOT NULL,at timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT(scan_id,lease_id,step)
);
CREATE INDEX ON scan_activity(scan_id,id);
CREATE TABLE agents (
    id uuid PRIMARY KEY,name text NOT NULL,token_hash bytea NOT NULL UNIQUE,
    registered_at timestamptz NOT NULL,last_seen_at timestamptz,details jsonb NOT NULL DEFAULT '{}'
);
CREATE TABLE agent_jobs (
    lease_id uuid PRIMARY KEY,agent_id uuid NOT NULL REFERENCES agents ON DELETE CASCADE,
    scan_id uuid NOT NULL REFERENCES scan_directory(id),assigned_at timestamptz NOT NULL,
    finished_at timestamptz,error text
);
CREATE INDEX ON agent_jobs(agent_id,assigned_at DESC,lease_id);
CREATE TABLE schedules (
    id uuid PRIMARY KEY,name text NOT NULL,reference text NOT NULL,platform text NOT NULL,
    registry_id uuid REFERENCES registries,source text NOT NULL,expression text NOT NULL,
    enabled boolean NOT NULL,due_at timestamptz NOT NULL,selection jsonb
);
CREATE INDEX ON schedules(due_at,id) WHERE enabled;
CREATE TABLE schedule_runs (
    id uuid PRIMARY KEY,schedule_id uuid REFERENCES schedules ON DELETE SET NULL,name text NOT NULL,
    nominal_time timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),trigger text NOT NULL
);
CREATE UNIQUE INDEX schedule_run_once ON schedule_runs(schedule_id,nominal_time) WHERE trigger='schedule';
CREATE TABLE schedule_run_scans (
    run_id uuid REFERENCES schedule_runs,scan_id uuid REFERENCES scan_directory(id),PRIMARY KEY(run_id,scan_id)
);

CREATE FUNCTION enqueue_scan(job uuid, image text, platform_name text, origin text, registry uuid,
                            engines text[], weight integer) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    queued timestamptz := clock_timestamp();
BEGIN
    PERFORM prepare_storage_months(queued);
    INSERT INTO scan_directory(id,queued_at) VALUES(job,queued);
    INSERT INTO scans(id,queued_at,reference,platform,status,priority)
        VALUES(job,queued,image,platform_name,'queued',weight);
    INSERT INTO scan_jobs(scan_id,priority,queued_at,source,registry_id,scanners)
        VALUES(job,weight,queued,origin,registry,engines);
    PERFORM pg_notify('certhia_work','');
    PERFORM pg_notify('certhia_activity',job::text);
END $$;

CREATE FUNCTION claim_scan(owner_id uuid, allowed_sources text[], remote_agent boolean)
RETURNS SETOF scan_jobs LANGUAGE plpgsql AS $$
DECLARE
    job scan_jobs;
BEGIN
    WITH candidate AS (
        SELECT scan_id FROM scan_jobs
        WHERE source=ANY(allowed_sources) AND (lease_until IS NULL OR lease_until <= statement_timestamp())
        ORDER BY priority DESC,queued_at,scan_id LIMIT 1 FOR UPDATE SKIP LOCKED
    ) UPDATE scan_jobs j SET lease_id=gen_random_uuid(),worker=owner_id,
        attempts=attempts+1,lease_until=clock_timestamp()+interval '60 seconds'
        FROM candidate c WHERE j.scan_id=c.scan_id RETURNING j.* INTO job;
    IF NOT FOUND THEN RETURN; END IF;
    UPDATE scans SET status='running',started_at=clock_timestamp() WHERE id=job.scan_id AND queued_at=job.queued_at;
    IF remote_agent THEN
        INSERT INTO agent_jobs VALUES(job.lease_id,owner_id,job.scan_id,clock_timestamp(),NULL,NULL);
    END IF;
    INSERT INTO scan_activity(scan_id,lease_id,step,title,detail)
        VALUES(job.scan_id,job.lease_id,'started','Preparing scan','A worker claimed the scan.');
    PERFORM pg_notify('certhia_activity',job.scan_id::text);
    RETURN NEXT job;
END $$;

CREATE FUNCTION renew_scan(job uuid, token uuid, owner_id uuid) RETURNS boolean LANGUAGE sql AS $$
    WITH renewed AS (
        UPDATE scan_jobs SET lease_until=clock_timestamp()+interval '60 seconds'
        WHERE scan_id=job AND lease_id=token AND worker=owner_id AND lease_until>clock_timestamp()
        RETURNING scan_id
    ) SELECT EXISTS(SELECT FROM renewed)
$$;

-- Invoke in the same transaction as the result merge. No other worker can
-- reclaim the row while this transaction holds its lock.
CREATE FUNCTION finish_scan(job uuid, token uuid, owner_id uuid, failure text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    queued timestamptz;
BEGIN
    DELETE FROM scan_jobs WHERE scan_id=job AND lease_id=token AND worker=owner_id
        AND lease_until>clock_timestamp() RETURNING queued_at INTO queued;
    IF NOT FOUND THEN RAISE EXCEPTION 'Scan lease expired or superseded' USING ERRCODE='P0002'; END IF;
    UPDATE scans SET status=CASE WHEN failure IS NULL THEN 'completed' ELSE 'failed' END,
        error=failure,finished_at=clock_timestamp() WHERE id=job AND queued_at=queued;
    UPDATE agent_jobs SET finished_at=clock_timestamp(),error=failure WHERE lease_id=token;
    PERFORM pg_notify('certhia_activity',job::text);
END $$;

-- The scheduler supplies the next cron occurrence after matching the persisted
-- schedule. If another scheduler has advanced it, there is no run to enqueue.
CREATE FUNCTION fire_schedule(schedule uuid, expected_due timestamptz, next_due timestamptz, run uuid)
RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE
    schedule_name text;
BEGIN
    IF next_due<=expected_due THEN RAISE EXCEPTION 'Next occurrence must advance'; END IF;
    UPDATE schedules SET due_at=next_due WHERE id=schedule AND enabled AND due_at=expected_due
        AND due_at<=clock_timestamp() RETURNING name INTO schedule_name;
    IF NOT FOUND THEN RETURN false; END IF;
    INSERT INTO schedule_runs(id,schedule_id,name,nominal_time,trigger)
        VALUES(run,schedule,schedule_name,expected_due,'schedule');
    RETURN true;
END $$;

CREATE FUNCTION record_scan_progress(job uuid, token uuid, owner_id uuid, stage text, label text, message text)
RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    PERFORM FROM scan_jobs WHERE scan_id=job AND lease_id=token AND worker=owner_id
        AND lease_until>clock_timestamp() FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    INSERT INTO scan_activity(scan_id,lease_id,step,title,detail) VALUES(job,token,stage,label,message)
        ON CONFLICT(scan_id,lease_id,step) DO NOTHING;
    IF FOUND THEN PERFORM pg_notify('certhia_activity',job::text); END IF;
    RETURN true;
END $$;
