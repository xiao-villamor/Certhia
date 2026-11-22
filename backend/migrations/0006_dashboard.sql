-- Split counters so independent digest merges need not lock the same five rows.
CREATE TABLE dashboard_counts (
    bucket smallint NOT NULL,
    severity_id smallint REFERENCES severities,
    total bigint NOT NULL,
    PRIMARY KEY(bucket,severity_id)
);
INSERT INTO dashboard_counts
    SELECT (digest_id%64)::smallint,severity_id,sum(total) FROM digest_severity_counts GROUP BY 1,2;

CREATE FUNCTION add_dashboard_counts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO dashboard_counts
        SELECT (digest_id%64)::smallint,severity_id,sum(total) FROM added GROUP BY 1,2 ORDER BY 1,2
        ON CONFLICT(bucket,severity_id) DO UPDATE SET total=dashboard_counts.total+excluded.total;
    RETURN NULL;
END $$;
CREATE FUNCTION subtract_dashboard_counts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE dashboard_counts d SET total=d.total-s.total FROM (
        SELECT (digest_id%64)::smallint AS bucket,severity_id,sum(total) AS total FROM removed GROUP BY 1,2
    ) s WHERE d.bucket=s.bucket AND d.severity_id=s.severity_id;
    RETURN NULL;
END $$;
CREATE TRIGGER dashboard_increment AFTER INSERT ON digest_severity_counts REFERENCING NEW TABLE AS added
    FOR EACH STATEMENT EXECUTE FUNCTION add_dashboard_counts();
CREATE TRIGGER dashboard_decrement AFTER DELETE ON digest_severity_counts REFERENCING OLD TABLE AS removed
    FOR EACH STATEMENT EXECUTE FUNCTION subtract_dashboard_counts();
CREATE TRIGGER dashboard_update_old AFTER UPDATE ON digest_severity_counts REFERENCING OLD TABLE AS removed
    FOR EACH STATEMENT EXECUTE FUNCTION subtract_dashboard_counts();
CREATE TRIGGER dashboard_update_new AFTER UPDATE ON digest_severity_counts REFERENCING NEW TABLE AS added
    FOR EACH STATEMENT EXECUTE FUNCTION add_dashboard_counts();
