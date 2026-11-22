// Run two normal HTTP servers, each with one local worker and a deterministic scanner.
use anyhow::{Context, Result};
use reqwest::{StatusCode, header};
use serde_json::{Value, json};
use std::{net::TcpListener, os::unix::fs::PermissionsExt, path::Path, time::Duration};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::process::{Child, Command};

const ADMIN_EMAIL: &str = "replica-admin@example.test";
const ADMIN_PASSWORD: &str = "replica-fixture-admin";
const VIEWER_EMAIL: &str = "replica-viewer@example.test";
const VIEWER_PASSWORD: &str = "replica-fixture-viewer";

async fn sign_in(
    client: &reqwest::Client,
    api: &str,
    email: &str,
    password: &str,
) -> Result<String> {
    let origin = reqwest::Url::parse(api)?.origin().ascii_serialization();
    let response = client
        .post(format!("{api}/auth/login"))
        .header(header::ORIGIN, origin)
        .json(&json!({"email":email, "password":password}))
        .send()
        .await?
        .error_for_status()?;
    Ok(response
        .headers()
        .get(header::SET_COOKIE)
        .context("sign-in did not set a session cookie")?
        .to_str()?
        .split(';')
        .next()
        .context("empty session cookie")?
        .to_owned())
}

async fn replica(db: &str, data: &Path, bin: &Path) -> Result<(Child, String)> {
    let addr = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let path = std::env::join_paths(std::iter::once(bin.to_path_buf()).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
    ))?;
    let child = Command::new(env!("CARGO_BIN_EXE_digestdesk"))
        .env("DATABASE_URL", db)
        .env_remove("DATABASE_READ_URL")
        .env("CERTHIA_BIND", addr.to_string())
        .env("CERTHIA_DATA_DIR", data)
        .env("CERTHIA_ALLOWED_HOSTS", "127.0.0.1")
        .env("CERTHIA_AUTH_LOCAL", "1")
        .env("CERTHIA_AUTH_SECURE_COOKIE", "0")
        .env_remove("CERTHIA_AUTH_ORIGIN")
        .env_remove("CERTHIA_AUTH_TRUSTED_PROXIES")
        .env_remove("CERTHIA_OIDC_PROVIDERS")
        .env_remove("CERTHIA_OIDC_PROVIDERS_FILE")
        .env_remove("CERTHIA_SETUP_TOKEN")
        .env_remove("CERTHIA_SETUP_TOKEN_FILE")
        .env("CERTHIA_ADMIN_EMAIL", ADMIN_EMAIL)
        .env("CERTHIA_ADMIN_PASSWORD", ADMIN_PASSWORD)
        .env_remove("CERTHIA_ADMIN_PASSWORD_FILE")
        .env("CERTHIA_MAX_CONCURRENT_SCANS", "1")
        .env("PATH", path)
        .kill_on_drop(true)
        .spawn()?;
    let url = format!("http://{addr}/api");
    let client = reqwest::Client::new();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if client
                .get(format!("{url}/ready"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("replica failed readiness")?;
    Ok((child, url))
}

#[tokio::test]
async fn batch_has_one_result_per_job_across_worker_crash() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pg = GenericImage::new("postgres", "17-alpine")
        .with_exposed_port(5432.tcp())
        .with_wait_for(WaitFor::message_on_stderr("listening on IPv4 address"))
        .with_env_var("POSTGRES_PASSWORD", "fixture")
        .start()
        .await?;
    let db = format!(
        "postgres://postgres:fixture@{}:{}/postgres",
        pg.get_host().await?,
        pg.get_host_port_ipv4(5432).await?
    );
    let data = tempfile::tempdir()?;
    let bin = tempfile::tempdir()?;
    let scanner = bin.path().join("trivy");
    std::fs::write(
        &scanner,
        r#"#!/bin/sh
set -eu
while [ "$1" != "--output" ]; do shift; done
out=$2
ref=""
for arg do ref=$arg; done
printf '%s\n' '{"SchemaVersion":2,"ArtifactType":"container_image","Results":[{"Type":"apk","Packages":[{"Name":"fixture","Version":"1"}],"Vulnerabilities":[{"VulnerabilityID":"FIXTURE","PkgName":"fixture","InstalledVersion":"1","Severity":"HIGH"}]}]}' > "$out"
printf '%s\n' "$ref" >> "$CERTHIA_DATA_DIR/calls"
printf '%s\n' "$CERTHIA_BIND" >> "$CERTHIA_DATA_DIR/owners"
sleep 0.15
if mkdir "$CERTHIA_DATA_DIR/first" 2>/dev/null; then
    sleep 3
fi
"#,
    )?;
    std::fs::set_permissions(scanner, std::fs::Permissions::from_mode(0o700))?;
    let (mut first, entry) = replica(&db, data.path(), bin.path()).await?;
    let scans = (0..8)
        .map(|i| json!({"reference":format!("example.org/fixture:{i}"),"platform":"linux/amd64"}))
        .collect::<Vec<_>>();
    let client = reqwest::Client::new();
    let origin = reqwest::Url::parse(&entry)?.origin().ascii_serialization();
    let admin = sign_in(&client, &entry, ADMIN_EMAIL, ADMIN_PASSWORD).await?;
    assert_eq!(
        client.get(format!("{entry}/scans")).send().await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .post(format!("{entry}/scans/bulk"))
            .header(header::COOKIE, &admin)
            .json(&json!({"scans":scans}))
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    client.post(format!("{entry}/users")).header(header::COOKIE, &admin).header(header::ORIGIN, &origin)
        .json(&json!({"email":VIEWER_EMAIL,"displayName":"Viewer","password":VIEWER_PASSWORD,"role":"viewer"}))
        .send().await?.error_for_status()?;
    let viewer = sign_in(&client, &entry, VIEWER_EMAIL, VIEWER_PASSWORD).await?;
    assert_eq!(
        client
            .post(format!("{entry}/scans/bulk"))
            .header(header::COOKIE, viewer)
            .header(header::ORIGIN, &origin)
            .json(&json!({"scans":scans}))
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    let batch: Value = client
        .post(format!("{entry}/scans/bulk"))
        .header(header::COOKIE, &admin)
        .header(header::ORIGIN, &origin)
        .json(&json!({"scans":scans}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(batch["scanIds"].as_array().unwrap().len(), 8);
    tokio::time::timeout(Duration::from_secs(30), async {
        while !data.path().join("first").exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    first.kill().await?;
    let pool = sqlx::PgPool::connect(&db).await?;
    // Advance the expired lease in this disposable database to keep the test fast.
    let expired = sqlx::query(
        "UPDATE scan_jobs SET lease_until=now()-interval '1 second' WHERE lease_id IS NOT NULL",
    )
    .execute(&pool)
    .await?;
    assert_eq!(expired.rows_affected(), 1);
    let ((_a, second_entry), (_b, _)) = tokio::try_join!(
        replica(&db, data.path(), bin.path()),
        replica(&db, data.path(), bin.path())
    )?;
    let account: Value = client
        .get(format!("{second_entry}/auth/me"))
        .header(header::COOKIE, &admin)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(account["user"]["email"], ADMIN_EMAIL);
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM scan_jobs")
                .fetch_one(&pool)
                .await?;
            if waiting == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<(), sqlx::Error>(())
    })
    .await??;
    let completed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM scans WHERE status='completed' AND raw_report_ref IS NOT NULL",
    )
    .fetch_one(&pool)
    .await?;
    let findings: i64 = sqlx::query_scalar("SELECT count(*) FROM findings")
        .fetch_one(&pool)
        .await?;
    assert_eq!((completed, findings), (8, 1));
    let owners = std::fs::read_to_string(data.path().join("owners"))?;
    assert_eq!(
        owners
            .lines()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    let calls = std::fs::read_to_string(data.path().join("calls"))?;
    assert_eq!(calls.lines().count(), 9);
    assert_eq!(
        calls
            .lines()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        8
    );
    Ok(())
}
