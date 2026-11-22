use anyhow::{Context, Result, ensure};
use sqlx::{PgPool, migrate::Migrator, postgres::PgPoolOptions};
use std::{env, time::Duration};

static MIGRATIONS: Migrator = sqlx::migrate!();

/// Migrations whose text changed after release (renamed notification channels and
/// settings). The SQL they create is replaced by migration 14, so databases that
/// applied the earlier text only need their recorded checksum updated.
const REVISED_MIGRATIONS: [(i64, &str); 4] = [
    (
        3,
        "890bee925c62c2c01adba57075cae76167f18bafc59d7e41870f62aa4767e8c8f5170b9096a0fb168539353f6dc86541",
    ),
    (
        7,
        "d154c4ed0ad8c69271218ede4bce37c9e4395150331481c9f07439a946cef74f39e9cf099929294807914848e4422f28",
    ),
    (
        8,
        "3a6c0581c8ee0a2f706c993a67fded5013c66918647658e73837158275d32c1999a89e7f64216a76e34531a310d20ffa",
    ),
    (
        11,
        "306316c57fe05f01555fe2584f740b0154286954d79a9ce9bba1596f8e2cf6c246a9a9a8df0cb9ca372fbef0aed43696",
    ),
];

async fn accept_revised_migrations(pool: &PgPool) -> Result<()> {
    let recorded: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(pool)
        .await?;
    if !recorded {
        return Ok(());
    }
    for (version, previous) in REVISED_MIGRATIONS {
        let current = MIGRATIONS
            .iter()
            .find(|migration| migration.version == version)
            .context("Revised migration is missing")?;
        sqlx::query(
            "UPDATE _sqlx_migrations SET checksum=$1 WHERE version=$2 AND checksum=decode($3,'hex')",
        )
        .bind(current.checksum.as_ref())
        .bind(version)
        .bind(previous)
        .execute(pool)
        .await?;
    }
    Ok(())
}

pub struct Database {
    pub primary: PgPool,
    pub reads: PgPool,
}

impl Database {
    pub async fn connect() -> Result<Self> {
        let url = env::var("DATABASE_URL").context("DATABASE_URL is required")?;
        Self::open(&url, env::var("DATABASE_READ_URL").ok().as_deref()).await
    }

    async fn open(url: &str, read_url: Option<&str>) -> Result<Self> {
        let options = PgPoolOptions::new()
            .max_connections(8)
            .min_connections(0)
            .acquire_timeout(Duration::from_secs(3));
        let primary = options.clone().connect(url).await?;
        let version = sqlx::query_scalar!(
            r#"SELECT current_setting('server_version_num')::integer AS "version!""#
        )
        .fetch_one(&primary)
        .await?;
        ensure!(version >= 160000, "PostgreSQL 16 or later is required");
        accept_revised_migrations(&primary).await?;
        MIGRATIONS.run(&primary).await?;
        let reads = match read_url {
            Some(url) if !url.is_empty() => options.connect_lazy(url)?,
            _ => primary.clone(),
        };
        Ok(Self { primary, reads })
    }

    pub async fn audit(&self, action: &str, resource: &str, detail: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_events(action,resource,detail,actor_user_id) VALUES($1,$2,$3,$4)",
        )
        .bind(action)
        .bind(resource)
        .bind(detail)
        .bind(crate::auth::actor())
        .execute(&self.primary)
        .await?;
        Ok(())
    }
    pub async fn ready(&self) -> Result<()> {
        let applied = sqlx::query!("SELECT version, checksum FROM _sqlx_migrations WHERE success")
            .fetch_all(&self.primary)
            .await?;
        ensure!(
            MIGRATIONS.iter().all(|m| applied
                .iter()
                .any(|r| r.version == m.version && r.checksum == m.checksum.as_ref())),
            "Storage migrations are incomplete"
        );
        sqlx::query!("SELECT 1 AS probe")
            .fetch_one(&self.reads)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testcontainers::{
        GenericImage, ImageExt,
        core::{IntoContainerPort, WaitFor},
        runners::AsyncRunner,
    };

    async fn instance() -> Result<(testcontainers::ContainerAsync<GenericImage>, String)> {
        let postgres = GenericImage::new("postgres", "17-alpine")
            .with_exposed_port(5432.tcp())
            .with_wait_for(WaitFor::message_on_stderr("listening on IPv4 address"))
            .with_env_var("POSTGRES_PASSWORD", "test")
            .start()
            .await?;
        let host = postgres.get_host().await?;
        let port = postgres.get_host_port_ipv4(5432).await?;
        let url = format!("postgres://postgres:test@{host}:{port}/postgres");
        Ok((postgres, url))
    }

    #[tokio::test]
    async fn concurrent_startup_and_readiness() -> Result<()> {
        let (_container, url) = instance().await?;
        let (a, b) = tokio::try_join!(Database::open(&url, None), Database::open(&url, None))?;
        tokio::try_join!(a.ready(), b.ready())?;
        sqlx::query("UPDATE _sqlx_migrations SET success=false WHERE version=1")
            .execute(&a.primary)
            .await?;
        assert!(b.ready().await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn rescan_resolves_and_reopens_one_finding() -> Result<()> {
        use crate::domain::{Captured, ImageReference};
        use serde_json::json;
        let (_container, url) = instance().await?;
        let db = Database::open(&url, None).await?;
        let data = tempfile::tempdir()?;
        let reference = ImageReference::parse("example.org/team/image:latest", None)?;
        for visible in [true, true, false, true] {
            let findings = if visible {
                json!([{"VulnerabilityID":"FIXTURE-1","Severity":"HIGH","PkgName":"openssl","InstalledVersion":"3"}])
            } else {
                json!([])
            };
            let report = json!({"SchemaVersion":2,"ArtifactType":"container_image",
                "Metadata":{"RepoDigests":[format!("example.org/team/image@sha256:{}","a".repeat(64))]},
                "Results":[{"Type":"alpine","Packages":[{"Name":"openssl","Version":"3"}],"Vulnerabilities":findings}]});
            let captured = Captured::from_trivy(&serde_json::to_vec(&report)?)?;
            crate::ingest::import(&db, data.path(), &reference, "linux/amd64", captured).await?;
            let open: i64 =
                sqlx::query_scalar("SELECT count(*) FROM findings WHERE resolved_scan_id IS NULL")
                    .fetch_one(&db.primary)
                    .await?;
            assert_eq!(open, i64::from(visible));
            let count: i64 = sqlx::query_scalar(
                "SELECT total FROM repository_severity_counts WHERE severity_id=3",
            )
            .fetch_one(&db.primary)
            .await?;
            assert_eq!(count, open);
        }
        let (findings,packages,changes):(i64,i64,i64)=sqlx::query_as(
            "SELECT (SELECT count(*) FROM findings),(SELECT count(*) FROM digest_packages),(SELECT count(*) FROM finding_transitions)"
        ).fetch_one(&db.primary).await?;
        assert_eq!((findings, packages, changes), (1, 1, 3));
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_claims_and_expired_lease_recovery() -> Result<()> {
        use uuid::Uuid;
        let (_container, url) = instance().await?;
        let first = Database::open(&url, None).await?;
        let second = Database::open(&url, None).await?;
        let ids: Vec<_> = (0..12).map(|_| Uuid::now_v7()).collect();
        for id in &ids {
            sqlx::query("SELECT enqueue_scan($1,'example.org/test:latest','linux/amd64','registry',NULL,'{}',0)")
                .bind(id).execute(&first.primary).await?;
        }
        let owner_a = Uuid::now_v7();
        let owner_b = Uuid::now_v7();
        async fn claim(pool: &PgPool, owner: Uuid) -> Result<(Uuid, Uuid)> {
            Ok(
                sqlx::query_as("SELECT scan_id,lease_id FROM claim_scan($1,ARRAY['registry'])")
                    .bind(owner)
                    .fetch_one(pool)
                    .await?,
            )
        }
        let mut claims = Vec::new();
        for _ in 0..6 {
            let (a, b) = tokio::try_join!(
                claim(&first.primary, owner_a),
                claim(&second.primary, owner_b)
            )?;
            claims.push((a, owner_a));
            claims.push((b, owner_b));
        }
        let claimed: std::collections::HashSet<_> = claims.iter().map(|((id, _), _)| *id).collect();
        assert_eq!(claimed, ids.into_iter().collect());
        let ((id, stale), owner) = claims.pop().unwrap();
        sqlx::query("UPDATE scan_jobs SET lease_until=now()-interval '1 second' WHERE scan_id=$1")
            .bind(id)
            .execute(&first.primary)
            .await?;
        let (reclaimed, new) = claim(&first.primary, owner_a).await?;
        assert_eq!(id, reclaimed);
        assert_ne!(new, stale);
        let renewed: bool = sqlx::query_scalar("SELECT renew_scan($1,$2,$3)")
            .bind(id)
            .bind(stale)
            .bind(owner)
            .fetch_one(&second.primary)
            .await?;
        assert!(!renewed);
        let finish = "SELECT finish_scan($1,$2,$3,NULL)";
        assert!(
            sqlx::query(finish)
                .bind(id)
                .bind(stale)
                .bind(owner)
                .execute(&second.primary)
                .await
                .is_err()
        );
        claims.push(((id, new), owner_a));
        for ((scan, token), owner) in claims {
            sqlx::query(finish)
                .bind(scan)
                .bind(token)
                .bind(owner)
                .execute(&first.primary)
                .await?;
        }
        let completed: i64 =
            sqlx::query_scalar("SELECT count(*) FROM scans WHERE status='completed'")
                .fetch_one(&first.primary)
                .await?;
        assert_eq!(completed, 12);
        Ok(())
    }

    #[tokio::test]
    async fn scheduled_enqueue_is_atomic_and_wakes_listener() -> Result<()> {
        use sqlx::postgres::PgListener;
        use uuid::Uuid;
        let (_container, url) = instance().await?;
        let db = Database::open(&url, None).await?;
        let mut listener = PgListener::connect(&url).await?;
        listener.listen("certhia_work").await?;
        let schedule = Uuid::now_v7();
        sqlx::query("INSERT INTO schedules(id,name,reference,platform,source,expression,enabled,due_at)
            VALUES($1,'daily','example.org/test','linux/amd64','registry','0 0 * * *',true,'2020-01-01Z')")
            .bind(schedule).execute(&db.primary).await?;
        async fn run(pool: &PgPool, schedule: Uuid) -> Result<bool> {
            let mut tx = pool.begin().await?;
            let run = Uuid::now_v7();
            let won: bool =
                sqlx::query_scalar("SELECT fire_schedule($1,'2020-01-01Z','2020-01-02Z',$2)")
                    .bind(schedule)
                    .bind(run)
                    .fetch_one(&mut *tx)
                    .await?;
            if won {
                let job = Uuid::now_v7();
                sqlx::query("SELECT enqueue_scan($1,'example.org/test','linux/amd64','registry',NULL,'{}',0)")
                    .bind(job).execute(&mut *tx).await?;
                sqlx::query("INSERT INTO schedule_run_scans VALUES($1,$2)")
                    .bind(run)
                    .bind(job)
                    .execute(&mut *tx)
                    .await?;
            }
            tx.commit().await?;
            Ok(won)
        }
        let (a, b) = tokio::try_join!(run(&db.primary, schedule), run(&db.primary, schedule))?;
        assert_ne!(a, b);
        let wake = tokio::time::timeout(Duration::from_secs(3), listener.recv()).await??;
        assert_eq!(wake.channel(), "certhia_work");
        Ok(())
    }
}
