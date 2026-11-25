mod analytics;
mod api_spec;
mod artifact_blob;
mod artifacts;
mod auth;
mod automation;
mod benchmarks;
mod comparison;
mod discovery;
mod discrepancies;
mod domain;
mod exports;
mod images;
mod ingest;
mod issue_trackers;
mod jobs;
mod native_scanners;
mod operations;
mod patches;
mod pg_scans;
mod postgres;
mod registries;
mod report_branding;
mod report_pages;
mod report_pdf;
mod scanner;
mod store;
mod telemetry;
mod watches;
mod webhooks;

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, get_service, post},
};
use domain::{Captured, ImageReference, PLATFORMS, compare, registry_host};
use scanner::{Credentials, MAX_REPORT_BYTES, Vault};
use serde::Deserialize;
use serde_json::json;
use std::{env, path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::Notify;
use tower_http::services::{ServeDir, ServeFile};
use uuid::Uuid;

const PRODUCT_NAME: &str = "Certhia";

#[derive(Clone)]
struct App(Arc<AppState>);

struct AppState {
    database: postgres::Database,
    vault: Vault,
    cache: PathBuf,
    work: Notify,
    progress: tokio::sync::broadcast::Sender<String>,
    patch_slot: tokio::sync::Semaphore,
    data: PathBuf,
    allowed_hosts: Vec<String>,
    auth: auth::Config,
}

#[derive(Debug, thiserror::Error)]
#[error("{1}")]
struct ApiError(StatusCode, String);

#[derive(Deserialize, Default)]
struct IdPage {
    cursor: Option<Uuid>,
    limit: Option<i64>,
}
impl IdPage {
    fn limit(&self) -> ApiResult<i64> {
        let limit = self.limit.unwrap_or(100);
        if (1..=250).contains(&limit) {
            Ok(limit)
        } else {
            Err(ApiError::bad("Choose a page size between 1 and 250."))
        }
    }
}

type List<T> = (HeaderMap, Json<Vec<T>>);
fn page_rows<T>(
    mut rows: Vec<T>,
    limit: i64,
    cursor: impl FnOnce(&T) -> String,
) -> ApiResult<List<T>> {
    let mut headers = HeaderMap::new();
    if rows.len() > limit as usize {
        rows.truncate(limit as usize);
        let next = cursor(rows.last().expect("positive limit"));
        headers.insert("x-next-cursor", next.parse().map_err(ApiError::bad)?);
    }
    Ok((headers, Json(rows)))
}
#[derive(Deserialize)]
struct ScanPage {
    cursor: Option<Uuid>,
    limit: Option<i64>,
    q: Option<String>,
    status: Option<String>,
    repository: Option<String>,
    platform: Option<String>,
}
impl ScanPage {
    fn limit(&self) -> ApiResult<i64> {
        IdPage {
            cursor: self.cursor,
            limit: self.limit,
        }
        .limit()
    }
}
fn key(id: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(id).map_err(|_| ApiError::missing("Unknown ID."))
}

impl ApiError {
    fn bad(error: impl ToString) -> Self {
        Self(StatusCode::BAD_REQUEST, error.to_string())
    }

    fn missing(message: &str) -> Self {
        Self(StatusCode::NOT_FOUND, message.to_owned())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        if error
            .downcast_ref::<sqlx::Error>()
            .and_then(|e| e.as_database_error())
            .and_then(|e| e.code())
            .is_some_and(|c| c == "P0002")
        {
            return Self(
                StatusCode::CONFLICT,
                "Scan lease expired or reassigned.".into(),
            );
        }
        tracing::error!(error = %error, "Internal API error");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The service could not complete the request.".into(),
        )
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        match &error {
            sqlx::Error::Database(db)
                if db
                    .code()
                    .is_some_and(|c| matches!(c.as_ref(), "P0002" | "23503" | "23505")) =>
            {
                Self(
                    StatusCode::CONFLICT,
                    "The resource changed before the request finished.".into(),
                )
            }
            sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => Self(
                StatusCode::SERVICE_UNAVAILABLE,
                "Database unavailable.".into(),
            ),
            _ => Self::from(anyhow::Error::from(error)),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegistryInput {
    name: String,
    host: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(flatten)]
    options: registries::Options,
}

#[derive(Deserialize)]
struct TestRegistry {
    host: String,
    reference: String,
    platform: Option<String>,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    protocol: Option<String>,
    #[serde(default, rename = "skipTls")]
    skip_tls: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanInput {
    reference: String,
    platform: String,
    registry_id: Option<String>,
    source: Option<String>,
    scanners: Option<Vec<String>>,
    priority: Option<i32>,
}

#[derive(Deserialize)]
struct CompareInput {
    baseline: String,
    target: String,
    publication: Option<Uuid>,
}

fn credentials(username: String, password: String) -> ApiResult<Option<Credentials>> {
    if username.is_empty() && password.is_empty() {
        return Ok(None);
    }
    if username.is_empty()
        || username.contains(':')
        || password.is_empty()
        || username.len() > 512
        || password.len() > 8192
    {
        return Err(ApiError::bad("Enter a username and a password or token."));
    }
    Ok(Some(Credentials { username, password }))
}

fn validate_platform(platform: &str) -> ApiResult<()> {
    if !PLATFORMS.contains(&platform) {
        return Err(ApiError::bad("Choose a supported Linux platform."));
    }
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

async fn ready(State(app): State<App>) -> ApiResult<Json<serde_json::Value>> {
    app.0.database.ready().await.map_err(|_| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Database unavailable or migrations incomplete".into(),
        )
    })?;
    Ok(Json(json!({ "status": "ok" })))
}

async fn add_registry(
    State(app): State<App>,
    Json(input): Json<RegistryInput>,
) -> ApiResult<(StatusCode, Json<store::Registry>)> {
    let name = input.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::bad(
            "Enter a registry name of up to 100 characters.",
        ));
    }
    let host = registry_host(&input.host).map_err(ApiError::bad)?;
    let secret = credentials(input.username.trim().to_owned(), input.password)?
        .map(|credentials| app.0.vault.seal(&host, &credentials))
        .transpose()?;
    let registry = registries::add(&app, name, &host, secret, input.options.validate()?).await?;
    app.0
        .database
        .audit("registry.added", &registry.id, &registry.host)
        .await?;
    Ok((StatusCode::CREATED, Json(registry)))
}

async fn remove_registry(State(app): State<App>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let key = Uuid::parse_str(&id).map_err(|_| ApiError::missing("Registry not found."))?;
    if sqlx::query!("DELETE FROM registry_profiles WHERE id=$1", key)
        .execute(&app.0.database.primary)
        .await?
        .rows_affected()
        == 0
    {
        return Err(ApiError::missing("Registry not found."));
    }
    app.0.database.audit("registry.removed", &id, "").await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn test_registry(Json(input): Json<TestRegistry>) -> ApiResult<Json<serde_json::Value>> {
    let host = registry_host(&input.host).map_err(ApiError::bad)?;
    let reference = ImageReference::parse(&input.reference, Some(&host)).map_err(ApiError::bad)?;
    let platform = input.platform.as_deref().unwrap_or(domain::PLATFORMS[0]);
    validate_platform(platform)?;
    let credentials = credentials(input.username.trim().to_owned(), input.password)?;
    images::verify_access(
        &reference,
        platform,
        credentials,
        input.skip_tls || input.protocol.as_deref() == Some("http"),
    )
    .await
    .map_err(ApiError::bad)?;
    Ok(Json(json!({ "reference": reference.value, "platform": platform })))
}

async fn list_scans(
    State(app): State<App>,
    Query(q): Query<ScanPage>,
) -> ApiResult<List<store::Scan>> {
    let limit = q.limit()?;
    page_rows(
        app.0
            .database
            .scan_page(
                q.cursor,
                limit + 1,
                q.q.as_deref(),
                q.status.as_deref(),
                q.repository.as_deref(),
                q.platform.as_deref(),
            )
            .await?,
        limit,
        |r| r.id.clone(),
    )
}

async fn scan_detail(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Json<store::ScanDetail>> {
    Ok(Json(read_scan_detail(&app, &id).await?))
}

async fn read_scan_detail(app: &App, id: &str) -> ApiResult<store::ScanDetail> {
    let mut scan = app
        .0
        .database
        .scan(id)
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    if let Some(report) = &mut scan.report
        && report.os.is_none()
        && report.observation_complete.is_none()
        && let Ok(Some(raw)) = artifacts::trivy(&app, &id).await
        && let Ok(saved) = domain::Report::from_trivy(&raw)
    {
        report.os = saved.os;
    }
    if let Some(report) = &mut scan.report
        && let Err(error) = artifacts::enrich(app, id, &scan.scan.source, report).await
    {
        tracing::warn!(scan_id=id, %error, "Could not load finding evidence");
        report.evidence_available = Some(false);
    }
    Ok(scan)
}

pub struct ImageTarget {
    pub reference: String,
    pub platform: String,
    pub registry_id: Option<String>,
    pub source: String,
    pub scanners: Vec<String>,
    pub priority: i32,
}

async fn image_target(app: &App, input: ScanInput) -> ApiResult<ImageTarget> {
    validate_platform(&input.platform)?;
    let source = input.source.unwrap_or_else(|| "registry".into());
    let (scanners, priority) = jobs::validate(input.scanners, input.priority)?;
    if source == "docker" {
        if input.registry_id.is_some() {
            return Err(ApiError::bad("Docker images use the local engine."));
        }
        discovery::socket()?;
        let reference = input.reference.trim().to_owned();
        let digest = reference
            .strip_prefix("sha256:")
            .is_some_and(|value| value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit()));
        if !digest {
            ImageReference::parse(&reference, None).map_err(ApiError::bad)?;
        }
        return Ok(ImageTarget {
            reference,
            platform: input.platform,
            registry_id: None,
            source,
            scanners,
            priority,
        });
    }
    if !matches!(source.as_str(), "registry" | "swarm" | "kubernetes") {
        return Err(ApiError::bad("Choose a supported image source."));
    }
    let owner = match &input.registry_id {
        Some(id) => Some(
            crate::registries::credential_record(app, id)
                .await?
                .ok_or_else(|| ApiError::missing("Saved registry not found."))?
                .0,
        ),
        None => None,
    };
    let reference = ImageReference::parse(&input.reference, owner.as_deref())
        .map_err(ApiError::bad)?
        .value;
    Ok(ImageTarget {
        reference,
        platform: input.platform,
        registry_id: input.registry_id,
        source,
        scanners,
        priority,
    })
}

async fn queue_scan(
    State(app): State<App>,
    Json(input): Json<ScanInput>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let input = image_target(&app, input).await?;
    let id = jobs::enqueue(&app, &input).await?.ok_or_else(|| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "The scan queue is full.".into(),
        )
    })?;
    app.0
        .database
        .audit("scan.queued", &id, &input.reference)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": id }))))
}

async fn import_scan(
    State(app): State<App>,
    Query(input): Query<ScanInput>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    if !content_type.is_some_and(|value| value.split(';').next() == Some("application/json")) {
        return Err(ApiError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Upload a Trivy JSON report.".into(),
        ));
    }
    validate_platform(&input.platform)?;
    let reference = ImageReference::parse(&input.reference, None).map_err(ApiError::bad)?;
    let report = tokio::task::spawn_blocking(move || Captured::from_trivy(&body))
        .await
        .map_err(anyhow::Error::from)?
        .map_err(ApiError::bad)?;
    let id = ingest::import(
        &app.0.database,
        &app.0.data,
        &reference,
        &input.platform,
        report,
    )
    .await?;
    app.0
        .database
        .audit("scan.imported", &id.to_string(), &reference.value)
        .await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ComparisonResponse {
    baseline: store::Scan,
    target: store::Scan,
    baseline_digest: Option<String>,
    target_digest: Option<String>,
    scanners: Vec<&'static str>,
    changes: domain::Comparison,
    baseline_scanners: Vec<&'static str>,
    target_scanners: Vec<&'static str>,
    publication: Option<String>,
    selected: Vec<SelectedAdvisory>,
    baseline_issues: serde_json::Value,
    target_issues: serde_json::Value,
}

#[derive(serde::Serialize)]
struct SelectedAdvisory {
    id: String,
    detected: bool,
}

async fn compare_scans(
    State(app): State<App>,
    Query(input): Query<CompareInput>,
) -> ApiResult<Response> {
    if input.baseline == input.target {
        return Err(ApiError::bad("Choose two different scans."));
    }
    let (baseline, target) = tokio::try_join!(
        app.0.database.scan(&input.baseline),
        app.0.database.scan(&input.target),
    )?;
    let baseline = baseline.ok_or_else(|| ApiError::missing("Baseline scan not found."))?;
    let target = target.ok_or_else(|| ApiError::missing("Target scan not found."))?;
    let incomplete = || ApiError::bad("Both scans must have completed reports.");
    let mut before = baseline.report.ok_or_else(incomplete)?;
    let mut after = target.report.ok_or_else(incomplete)?;
    if baseline.scan.platform != target.scan.platform {
        return Err(ApiError::bad("Choose two reports for the same platform."));
    }
    let (publication, selected) = if let Some(publication) = input.publication {
        let (pinned, packages): (String, serde_json::Value) = sqlx::query_as(
            "SELECT pub.pinned_reference,p.packages FROM patch_publications pub JOIN patches p ON p.id=pub.patch_id
             WHERE pub.id=$1 AND p.scan_id=$2 AND pub.scan_id=$3",
        )
        .bind(publication).bind(key(&input.baseline)?).bind(key(&input.target)?)
        .fetch_optional(&app.0.database.primary).await?
        .ok_or_else(|| ApiError::missing("Publication and scan pair not found."))?;
        let digest = pinned.rsplit_once('@').map(|(_, digest)| digest);
        if target.scan.reference != pinned || digest.is_none() || after.digest.as_deref() != digest {
            return Err(ApiError::bad(
                "The target report does not confirm the published manifest digest.",
            ));
        }
        let selected: std::collections::BTreeSet<String> = packages
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|package| package["advisories"].as_array().into_iter().flatten())
            .filter_map(|advisory| advisory.as_str().map(str::to_owned))
            .collect();
        (Some(pinned), selected)
    } else {
        (None, Default::default())
    };
    let (baseline_scanners, target_scanners) = if publication.is_some() {
        (vec!["trivy"], vec!["trivy"])
    } else {
        (
            comparison::engines(&before, &baseline.scan.source),
            comparison::engines(&after, &target.scan.source),
        )
    };
    let scanners = if publication.is_some() {
        (before, after) = tokio::try_join!(
            comparison::publication_report(&app, &baseline.scan, &before),
            comparison::publication_report(&app, &target.scan, &after)
        )?;
        vec!["trivy"]
    } else {
        comparison::align_findings(
            &app,
            (&input.baseline, &mut before, &baseline_scanners),
            (&input.target, &mut after, &target_scanners),
        )
        .await
    };
    let (before_issues, after_issues) = tokio::try_join!(
        comparison::issues(&app, &input.baseline),
        comparison::issues(&app, &input.target)
    )?;
    let bytes = tokio::task::spawn_blocking(move || {
        let selected = if selected.is_empty() {
            Vec::new()
        } else {
            let detected: std::collections::HashSet<_> = after
                .findings
                .iter()
                .map(|finding| finding.id.as_str())
                .collect();
            selected
                .into_iter()
                .map(|id| SelectedAdvisory {
                    detected: detected.contains(id.as_str()),
                    id,
                })
                .collect()
        };
        let changes = compare(&before, &after);
        serde_json::to_vec(&ComparisonResponse {
            baseline: baseline.scan,
            target: target.scan,
            baseline_digest: before.digest,
            target_digest: after.digest,
            scanners,
            changes,
            baseline_scanners,
            target_scanners,
            publication,
            selected,
            baseline_issues: before_issues,
            target_issues: after_issues,
        })
    })
    .await
    .map_err(anyhow::Error::from)?
    .map_err(anyhow::Error::from)?;
    Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}

async fn run_scan(app: &App, job: &store::Job, activity: jobs::Activity<'_>) -> Result<Captured> {
    let selected = jobs::effective_scanners(app, job).await?;
    let archive = app.0.data.join("archives").join(&job.id);
    let mut credentials = None;
    let reference;
    let target = match job.source.as_str() {
        "docker" => scanner::Target::Docker(&job.reference),
        "archive" => scanner::Target::Archive(&archive),
        _ => {
            activity
                .record(
                    "registry",
                    "Preparing registry access",
                    "Resolving the image reference and any saved pull credentials.",
                )
                .await;
            let (registry, secret) = match job.registry_id.as_deref() {
                Some(id) => registries::credential_record(app, id).await?.context(
                    "The saved registry was removed. Choose a registry and start a new scan.",
                )?,
                None => (String::new(), None),
            };
            reference = ImageReference::parse(
                &job.reference,
                job.registry_id.as_ref().map(|_| registry.as_str()),
            )?;
            credentials = secret
                .map(|value| app.0.vault.open_secret(&reference.host, &value))
                .transpose()?;
            scanner::Target::Remote(
                &reference,
                registries::insecure(app, job.registry_id.as_deref()).await?,
            )
        }
    };
    let captured = if selected == ["trivy"] && !matches!(target, scanner::Target::Remote(..)) {
        scanner::scan(target, &job.platform, &app.0.cache, activity).await?
    } else {
        native_scanners::scan(app, job, target, credentials, &selected, activity).await?
    };
    if let Some((_, digest)) = job.reference.rsplit_once('@') {
        let published_scan: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT FROM patch_publications WHERE scan_id=$1)")
                .bind(Uuid::parse_str(&job.id)?)
                .fetch_one(&app.0.database.primary)
                .await?;
        anyhow::ensure!(
            !published_scan || captured.report.digest.as_deref() == Some(digest),
            "The scan did not confirm the published manifest digest."
        );
    }
    Ok(captured)
}

async fn worker(app: App) {
    let owner = Uuid::now_v7();
    let sources = ["archive", "docker", "registry", "swarm", "kubernetes"].map(str::to_owned);
    loop {
        let wake = app.0.work.notified();
        tokio::pin!(wake);
        wake.as_mut().enable();
        let operation: Result<()> = async {
            let Some(lease) = jobs::claim(&app, owner, &sources).await? else {
                let expiry = sqlx::query_scalar!(
                    r#"SELECT min(lease_until) AS "expiry?" FROM scan_jobs WHERE source=ANY($1)"#,
                    &sources
                )
                .fetch_one(&app.0.database.primary)
                .await?;
                if let Some(expiry) = expiry {
                    let delay = (expiry - chrono::Utc::now()).to_std().unwrap_or_default();
                    tokio::select! {_=wake=>{},_=tokio::time::sleep(delay)=>{}}
                } else {
                    wake.await;
                }
                return Ok(());
            };
            let id = lease.scan.to_string();
            let job = app
                .0
                .database
                .replay(&id)
                .await?
                .context("Claimed scan missing")?;
            let activity = jobs::Activity {
                db: &app.0.database,
                lease,
            };
            let process = async {
                let result = run_scan(&app, &job, activity).await;
                let succeeded = result.is_ok();
                match result {
                    Ok(captured) => {
                        activity
                            .record(
                                "save",
                                "Saving the report",
                                "Storing package inventory and findings.",
                            )
                            .await;
                        let parsed = domain::ImageReference::parse(&job.reference, None)
                            .unwrap_or_else(|_| domain::ImageReference {
                                host: "local".into(),
                                value: job.reference.clone(),
                            });
                        ingest::write(
                            &app.0.database,
                            &app.0.data,
                            &parsed,
                            &job.platform,
                            captured,
                            Some(lease),
                        )
                        .await?;
                    }
                    Err(error) => {
                        sqlx::query!(
                            "SELECT finish_scan($1,$2,$3,$4)",
                            lease.scan,
                            lease.token,
                            lease.owner,
                            error.to_string()
                        )
                        .execute(&app.0.database.primary)
                        .await?;
                    }
                }
                Ok::<_, anyhow::Error>(succeeded)
            };
            let succeeded = tokio::select! {
                result=process=>result?,
                lost=async{
                    loop{
                        tokio::time::sleep(Duration::from_secs(15)).await;
                        if !jobs::heartbeat(&app,lease).await?{return Ok::<_,anyhow::Error>(());}
                    }
                }=>{lost?;return Ok(());}
            };
            let _ = app
                .0
                .database
                .audit(
                    if succeeded {
                        "scan.completed"
                    } else {
                        "scan.failed"
                    },
                    &id,
                    &job.reference,
                )
                .await;
            automation::publish_result(&app, &id, &job.reference, succeeded).await;
            Ok(())
        }
        .await;
        if let Err(error) = operation {
            tracing::warn!(%error,"Scan worker interrupted");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

async fn local_requests(State(app): State<App>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let host = auth::request_host(headers);
    if !host.is_some_and(|host| {
        app.0
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host.host()))
    }) {
        return ApiError(
            StatusCode::FORBIDDEN,
            format!("This hostname is not configured for {PRODUCT_NAME}."),
        )
        .into_response();
    }
    let is_api = request.uri().path().starts_with("/api/") || request.uri().path() == "/api";
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    // Keep the Origin header on same-origin form posts. API redirects carry no referrer.
    let referrer = if is_api { "no-referrer" } else { "same-origin" };
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, referrer.parse().unwrap());
    if is_api {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    }
    response
}

fn api_routes() -> Router<App> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/openapi.json", get(api_spec::schema))
        .route(
            "/version",
            get(|| async { Json(json!({"version":env!("CARGO_PKG_VERSION")})) }),
        )
        .route("/registries", get(registries::list).post(add_registry))
        .route("/registries/test", post(test_registry))
        .route("/registries/{id}", delete(remove_registry))
        .route("/scans", get(list_scans).post(queue_scan))
        .route(
            "/scans/import",
            post(import_scan).layer(DefaultBodyLimit::max(MAX_REPORT_BYTES)),
        )
        .route("/scans/{id}", get(scan_detail))
        .route("/compare", get(compare_scans))
        .merge(operations::routes())
        .merge(report_pages::routes())
        .merge(discovery::routes())
        .merge(automation::routes())
        .merge(report_branding::routes())
        .merge(registries::routes())
        .merge(images::routes())
        .merge(patches::routes())
        .merge(artifacts::routes())
        .merge(analytics::routes())
        .merge(jobs::routes())
        .merge(webhooks::routes())
        .merge(issue_trackers::routes())
        .merge(watches::routes())
        .merge(auth::routes())
        .merge(comparison::routes())
        .fallback(|| async { ApiError::missing("Endpoint not found.") })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.first().is_some_and(|name| name == "explain") {
        return discrepancies::cli(&args[1..]);
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    if args.first().is_some_and(|name| name == "bench") {
        return benchmarks::cli(&args[1..]).await;
    }
    telemetry::init()?;
    let data = PathBuf::from(env::var("CERTHIA_DATA_DIR").unwrap_or_else(|_| "data".into()));
    if args.as_slice() == ["benchmark-ingest"] {
        return ingest::benchmark(&data).await;
    }
    if args.first().is_some_and(|a| a == "reimport") {
        return ingest::reimport(&data, &args[1..]).await;
    }
    let web = PathBuf::from(env::var("CERTHIA_WEB_DIR").unwrap_or_else(|_| "../web/build".into()));
    let addr = env::var("CERTHIA_BIND").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let allowed_hosts: Vec<_> = env::var("CERTHIA_ALLOWED_HOSTS")
        .unwrap_or_else(|_| "localhost,127.0.0.1,[::1]".into())
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .collect();
    let auth::Startup { config } = auth::Config::load(&allowed_hosts)?;
    std::fs::create_dir_all(&data)?;
    let cache = data.join("trivy");
    std::fs::create_dir_all(&cache)?;
    std::fs::create_dir_all(data.join("archives"))?;
    std::fs::create_dir_all(data.join("patches"))?;
    let app = App(Arc::new(AppState {
        database: postgres::Database::connect().await?,

        vault: match env::var_os("CERTHIA_REGISTRY_KEY_FILE") {
            Some(path) => Vault::from_file(std::path::Path::new(&path))?,
            None => Vault::open(&data.join("registry.key"))?,
        },
        cache,
        work: Notify::new(),
        progress: tokio::sync::broadcast::channel(256).0,
        patch_slot: tokio::sync::Semaphore::new(1),
        data,
        allowed_hosts,
        auth: config,
    }));
    let recover = args.as_slice() == ["reset-admin-password"];
    auth::initialize(&app, recover).await?;
    if recover {
        return Ok(());
    }
    tokio::spawn(auth::cleanup(app.0.database.primary.clone()));
    tokio::spawn(jobs::listener(app.clone()));

    let concurrency = env::var("CERTHIA_MAX_CONCURRENT_SCANS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, 8);
    for _ in 0..concurrency {
        tokio::spawn(worker(app.clone()));
    }
    tokio::spawn(automation::clock(app.clone()));
    tokio::spawn(registries::sync(app.clone()));

    let api = api_routes().layer(middleware::from_fn_with_state(app.clone(), auth::authorize));

    let index = get_service(ServeFile::new(web.join("200.html")));
    let routes = Router::new()
        .nest("/api", api)
        .route("/", index.clone())
        .route("/scans/new", index.clone())
        .route("/scans/{id}", index.clone())
        .route("/registries", index.clone())
        .route("/images", index.clone())
        .route("/library", index.clone())
        .route("/library/{id}", index.clone())
        .route("/audit-logs", index.clone())
        .route("/scheduled-scans", index.clone())
        .route("/settings", index.clone())
        .route("/login", index.clone())
        .route("/setup", index.clone())
        .route("/welcome", index.clone())
        .route("/account", index.clone())
        .route("/patches", index.clone())
        .route("/api-reference", index.clone())
        .route("/api-docs", get(|| async { Redirect::permanent("/api-reference") }))
        .route("/repositories", index.clone())
        .route("/images/compare", index.clone())
        .route("/scheduled-scans/history", index.clone())
        .route("/compare", index)
        .fallback_service(ServeDir::new(&web).precompressed_br().precompressed_gzip().not_found_service(ServeFile::new(web.join("200.html"))))
        .layer(middleware::from_fn_with_state(app.clone(), local_requests))
        .layer(tower::ServiceBuilder::new()
            .layer(tower_http::request_id::SetRequestIdLayer::x_request_id(tower_http::request_id::MakeRequestUuid))
            .layer(tower_http::trace::TraceLayer::new_for_http().make_span_with(|request: &Request| {
                let route=request.extensions().get::<axum::extract::MatchedPath>().map_or("",|path| path.as_str());
                let request_id=request.headers().get("x-request-id").and_then(|h|h.to_str().ok()).unwrap_or("");
                tracing::info_span!("http.request", method=%request.method(), route, request_id)
            }).on_response(tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO)))
            .layer(tower_http::request_id::PropagateRequestIdLayer::x_request_id())
            .layer(tower_http::timeout::TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, scanner::scan_timeout()))
            .layer(tower_http::compression::CompressionLayer::new()))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Could not bind Certhia")?;
    tracing::info!(address=%listener.local_addr()?, "{PRODUCT_NAME} listening");
    axum::serve(
        listener,
        routes.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
