use crate::{
    ApiError, ApiResult, App, ImageReference,
    images::{self, Destination, Source},
    scanner::docker_config,
};
use anyhow::{Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
};

use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};
use tokio::process::Command;
use uuid::Uuid;

const FRONTEND: &str = "ghcr.io/project-copacetic/copacetic-frontend:v0.13.0@sha256:3535c95df9d2f13886940f96372b53b7647e391c035b5f4bd55fb27e7623a102";

fn buildkit_address() -> Option<String> {
    std::env::var("CERTHIA_BUILDKIT_ADDR")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub fn routes() -> Router<App> {
    Router::new()
        .route("/patches/analyze/{id}", get(analyze))
        .route("/patches/execute", post(execute))
        .route("/patches/history", get(history))
        .route("/patches/{id}/status", get(status))
        .route("/patches/{id}/download", get(download))
        .route("/patches/{id}/publish", post(publish))
}

fn candidates(report: &[u8]) -> Result<Vec<Value>> {
    let report: Value = serde_json::from_slice(report)?;
    let mut items = BTreeMap::<(String, String), Value>::new();
    for result in report["Results"].as_array().into_iter().flatten() {
        if result["Class"] != "os-pkgs" {
            continue;
        }
        for finding in result["Vulnerabilities"].as_array().into_iter().flatten() {
            let name = finding["PkgName"].as_str().unwrap_or_default();
            let fixed = finding["FixedVersion"].as_str().unwrap_or_default();
            if name.is_empty() || fixed.is_empty() {
                continue;
            }
            let node = items.entry((name.into(), fixed.into())).or_insert_with(|| json!({
                "package":name,"fixed":fixed,"installed":finding["InstalledVersion"],"advisories":[]
            }));
            if let (Some(list), Some(id)) = (
                node["advisories"].as_array_mut(),
                finding["VulnerabilityID"].as_str(),
            ) && !list.iter().any(|item| item == id)
            {
                list.push(json!(id));
            }
        }
    }
    Ok(items.into_values().collect())
}

async fn analyze(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let (_, detail) = images::load(&app, &id).await?;
    let raw = crate::artifacts::trivy(&app, &id)
        .await?
        .ok_or_else(|| ApiError::bad("Patch analysis requires a raw Trivy report."))?;
    let items = candidates(&raw)?;
    let available = detail
        .report
        .as_ref()
        .and_then(|report| report.digest.as_deref())
        .is_some()
        && buildkit_address().is_some()
        && !matches!(detail.scan.source.as_str(), "docker" | "archive");
    Ok(Json(
        json!({"image":detail.scan.reference,"packages":items,"canBuild":available}),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Input {
    scan_id: String,
    #[serde(default)]
    dry_run: bool,
    selected_vuln_ids: Option<Vec<String>>,
}

async fn execute(
    State(app): State<App>,
    Json(input): Json<Input>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let (job, detail) = images::load(&app, &input.scan_id).await?;
    let raw = crate::artifacts::trivy(&app, &input.scan_id)
        .await?
        .ok_or_else(|| ApiError::bad("Patch analysis requires a raw Trivy report."))?;
    let raw = match input.selected_vuln_ids {
        Some(ids) => {
            if ids.is_empty() || ids.len() > 5000 {
                return Err(ApiError::bad(
                    "Select at least one advisory and no more than 5,000.",
                ));
            }
            let ids: std::collections::HashSet<_> = ids.into_iter().collect();
            let mut report: Value = serde_json::from_slice(&raw).map_err(anyhow::Error::from)?;
            if let Some(results) = report["Results"].as_array_mut() {
                for result in results {
                    let os_packages = result["Class"] == "os-pkgs";
                    if let Some(findings) = result["Vulnerabilities"].as_array_mut() {
                        findings.retain(|finding| {
                            os_packages
                                && finding["VulnerabilityID"]
                                    .as_str()
                                    .is_some_and(|id| ids.contains(id))
                        });
                    }
                }
            }
            serde_json::to_vec(&report).map_err(anyhow::Error::from)?
        }
        None => raw,
    };
    let proposed = candidates(&raw)?;
    if proposed.is_empty() {
        return Err(ApiError::bad(
            "No fixed operating-system packages were found.",
        ));
    }
    let id = Uuid::now_v7().to_string();
    let address = if input.dry_run {
        None
    } else {
        if matches!(job.source.as_str(), "docker" | "archive") {
            return Err(ApiError::bad(
                "Publish the source image to a registry and scan it before building a patch.",
            ));
        }
        if detail
            .report
            .as_ref()
            .and_then(|report| report.digest.as_deref())
            .is_none()
        {
            return Err(ApiError::bad(
                "Scan the source registry image to record its digest first.",
            ));
        }
        Some(buildkit_address().ok_or_else(|| {
            ApiError::bad("Configure CERTHIA_BUILDKIT_ADDR to build patched images.")
        })?)
    };
    let state = if address.is_some() {
        "queued"
    } else {
        "planned"
    };
    let mut tx = app.0.database.primary.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(192387116)")
        .execute(&mut *tx)
        .await?;
    let inserted=sqlx::query!("INSERT INTO patches(id,scan_id,reference,platform,status,created_at,packages)
        SELECT $1,$2,$3,$4,$5,now(),$6 WHERE $5='planned' OR (SELECT count(*) FROM patches WHERE status IN ('queued','running'))<2",
        crate::key(&id)?,crate::key(&job.id)?,job.reference,job.platform,state,json!(proposed)).execute(&mut *tx).await?.rows_affected();
    tx.commit().await?;
    if inserted == 0 {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "The patch queue is full.".into(),
        ));
    }
    if let Some(address) = address {
        let app = app.clone();
        let key = id.clone();
        tokio::spawn(async move {
            let result = build(&app, &key, &address, &job, &detail, &raw).await;
            let _ = sqlx::query!(
                "UPDATE patches SET status=$2,finished_at=now(),error=$3 WHERE id=$1",
                Uuid::parse_str(&key).expect("generated ID"),
                if result.is_ok() {
                    "completed"
                } else {
                    "failed"
                },
                result.err().map(|e| e.to_string())
            )
            .execute(&app.0.database.primary)
            .await;
        });
    }
    app.0
        .database
        .audit(
            if input.dry_run {
                "patch.planned"
            } else {
                "patch.queued"
            },
            &id,
            &input.scan_id,
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id":id,"status":state}))))
}

async fn build(
    app: &App,
    id: &str,
    address: &str,
    job: &crate::store::Job,
    detail: &crate::store::ScanDetail,
    raw: &[u8],
) -> Result<()> {
    let _permit = app.0.patch_slot.acquire().await?;
    sqlx::query!(
        "UPDATE patches SET status='running' WHERE id=$1",
        Uuid::parse_str(id)?
    )
    .execute(&app.0.database.primary)
    .await?;
    let source = images::source(app, job, detail).await?;
    let context = tempfile::tempdir_in(app.0.data.join("patches"))?;
    let auth = tempfile::tempdir()?;
    let credentials = crate::registries::pull_credentials(&source.host, source.auth).await?;
    docker_config(&auth.path().join("config.json"), &source.host, credentials)?;
    tokio::fs::write(context.path().join("report.json"), raw).await?;
    let destination = context.path().join("patched.tar");
    let mut command = Command::new("buildctl");
    command
        .env("DOCKER_CONFIG", auth.path())
        .arg("--addr")
        .arg(address);
    for (environment, option) in [
        ("CERTHIA_BUILDKIT_CA", "--tlscacert"),
        ("CERTHIA_BUILDKIT_CERT", "--tlscert"),
        ("CERTHIA_BUILDKIT_KEY", "--tlskey"),
    ] {
        if let Some(path) = std::env::var_os(environment).filter(|value| !value.is_empty()) {
            command.arg(option).arg(path);
        }
    }
    command
        .arg("build")
        .args(["--frontend=gateway.v0", "--opt"])
        .arg(format!("source={FRONTEND}"))
        .arg("--opt")
        .arg(format!("image={}", source.reference))
        .arg("--opt")
        .arg(format!("platform={}", job.platform))
        .args([
            "--opt",
            "scanner=trivy",
            "--opt",
            "report=report.json",
            "--opt",
            "context:report=local:report",
            "--local",
        ])
        .arg(format!("report={}", context.path().display()))
        .arg("--output")
        .arg(format!("type=oci,dest={}", destination.display()));
    let output = tokio::time::timeout(
        Duration::from_secs(30 * 60),
        command.kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| anyhow!("BuildKit patch timed out."))?
    .map_err(|_| anyhow!("Could not run buildctl. Check the installed binary."))?;
    if !output.status.success() {
        bail!(
            "BuildKit could not build the patched image. Check worker connectivity and package availability."
        );
    }
    tokio::fs::rename(destination, app.0.data.join("patches").join(id)).await?;
    Ok(())
}

const SELECT: &str = "SELECT jsonb_build_object('id',id,'scanId',scan_id,'reference',reference,'platform',platform,'status',status,'createdAt',created_at,'finishedAt',finished_at,'error',error,'packages',packages) FROM patches";
async fn get_one(app: &App, id: &str) -> ApiResult<Value> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!("{SELECT} WHERE id=$1")))
        .bind(crate::key(id)?)
        .fetch_optional(&app.0.database.primary)
        .await?
        .ok_or_else(|| ApiError::missing("Patch operation not found."))
}
async fn status(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    Ok(Json(get_one(&app, &id).await?))
}
async fn history(
    State(app): State<App>,
    axum::extract::Query(page): axum::extract::Query<crate::IdPage>,
) -> ApiResult<crate::List<Value>> {
    let rows: Vec<Value> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE $1::uuid IS NULL OR id<$1 ORDER BY id DESC LIMIT $2"
    )))
    .bind(page.cursor)
    .bind(page.limit()? + 1)
    .fetch_all(&app.0.database.primary)
    .await?;
    crate::page_rows(rows, page.limit()?, |r| {
        r["id"].as_str().unwrap().to_owned()
    })
}
async fn download(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Response> {
    if get_one(&app, &id).await?["status"] != "completed" {
        return Err(ApiError::bad("The patch has not completed."));
    }
    images::attachment(
        app.0.data.join("patches").join(id),
        "patched-image.oci.tar",
        None,
    )
    .await
}

async fn publish(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(destination): Json<Destination>,
) -> ApiResult<Json<Value>> {
    let job = get_one(&app, &id).await?;
    if job["status"] != "completed" {
        return Err(ApiError::bad("The patch has not completed."));
    }
    let (target, auth, insecure) = images::destination(&app, destination).await?;
    if ImageReference::parse(job["reference"].as_str().unwrap_or_default(), None)
        .is_ok_and(|source| source.value == target.value)
    {
        return Err(ApiError::bad("Choose a new tag for the patched image."));
    }
    let path = app.0.data.join("patches").join(&id);
    let source = Source {
        transport: format!("oci-archive:{}", path.display()),
        host: String::new(),
        reference: String::new(),
        auth: None,
        insecure: false,
        platform: job["platform"].as_str().unwrap_or("linux/amd64").to_owned(),
    };
    images::copy(
        source,
        &format!("docker://{}", target.value),
        &target.host,
        auth,
        insecure,
    )
    .await
    .map_err(ApiError::bad)?;
    app.0
        .database
        .audit("patch.published", &id, &target.value)
        .await?;
    Ok(Json(json!({"reference":target.value})))
}
