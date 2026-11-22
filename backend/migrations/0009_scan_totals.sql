CREATE TABLE scan_status_counts (
    month date NOT NULL,bucket smallint NOT NULL,status text NOT NULL,total bigint NOT NULL,
    PRIMARY KEY(month,bucket,status)
);
INSERT INTO scan_status_counts
SELECT date_trunc('month',queued_at AT TIME ZONE 'UTC')::date,get_byte(uuid_send(id),15)%64,status,count(*)
FROM scans GROUP BY 1,2,3;

CREATE FUNCTION maintain_scan_status_counts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='UPDATE' AND OLD.status=NEW.status THEN RETURN NULL; END IF;
    IF TG_OP IN ('DELETE','UPDATE') THEN
        UPDATE scan_status_counts SET total=total-1 WHERE status=OLD.status AND
            month=date_trunc('month',OLD.queued_at AT TIME ZONE 'UTC')::date AND bucket=get_byte(uuid_send(OLD.id),15)%64;
    END IF;
    IF TG_OP IN ('INSERT','UPDATE') THEN
        INSERT INTO scan_status_counts VALUES(date_trunc('month',NEW.queued_at AT TIME ZONE 'UTC')::date,
            get_byte(uuid_send(NEW.id),15)%64,NEW.status,1)
        ON CONFLICT(month,bucket,status) DO UPDATE SET total=scan_status_counts.total+1;
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER scan_status_counts AFTER INSERT OR DELETE OR UPDATE OF status ON scans
    FOR EACH ROW EXECUTE FUNCTION maintain_scan_status_counts();
