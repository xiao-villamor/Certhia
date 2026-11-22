use crate::{
    ApiError, ApiResult, App, ImageReference, ImageTarget, ScanInput, image_target, images, jobs,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};

use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub fn routes() -> Router<App> {
    Router::new()
        .route("/compare/plan", post(plan))
        .route("/scans/{id}/previous", get(previous))
}

#[derive(Deserialize)]
struct Input {
    baseline: ScanInput,
    target: ScanInput,
}

async fn resolve(app: &App, input: &ImageTarget) -> ApiResult<String> {
    let reference = ImageReference::parse(&input.reference, None).map_err(ApiError::bad)?;
    let auth = images::credentials_for(app, input.registry_id.as_deref(), &reference.host)
        .await
        .map_err(ApiError::bad)?;
    images::pin(
        &reference,
        &input.platform,
        auth,
        crate::registries::insecure(app, input.registry_id.as_deref()).await?,
    )
    .await
    .map_err(ApiError::bad)
}

async fn plan(
    State(app): State<App>,
    Json(input): Json<Input>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let baseline = image_target(&app, input.baseline).await?;
    let target = image_target(&app, input.target).await?;
    if baseline.source != "registry" || target.source != "registry" {
        return Err(ApiError::bad(
            "Choose registry image references for this comparison.",
        ));
    }
    if baseline.platform != target.platform {
        return Err(ApiError::bad("Choose the same platform for both images."));
    }
    let (before, after) = tokio::try_join!(resolve(&app, &baseline), resolve(&app, &target))?;
    if before == after {
        return Err(ApiError::bad(
            "Both image references resolve to the same manifest.",
        ));
    }
    let mut tx = app.0.database.primary.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(192387115)")
        .execute(&mut *tx)
        .await?;
    let mut ids = Vec::new();
    for (mut input, pinned) in [(baseline, &before), (target, &after)] {
        let (name, digest) = pinned.rsplit_once('@').expect("resolved reference");
        let prior=sqlx::query_scalar!("SELECT s.id FROM scans s LEFT JOIN digests d ON d.id=s.digest_id
            LEFT JOIN repositories r ON r.id=s.repository_id LEFT JOIN registries g ON g.id=r.registry_id
            WHERE platform=$1 AND ((reference=$2 AND status IN ('queued','running')) OR
            (status='completed' AND d.digest=$3 AND g.host||'/'||r.name=$4))
            ORDER BY (status='completed') DESC,queued_at DESC,id DESC LIMIT 1",input.platform,pinned,digest,name).fetch_optional(&mut *tx).await?;
        if let Some(id) = prior {
            ids.push(id.to_string());
            continue;
        }
        let id = Uuid::now_v7().to_string();
        input.reference = pinned.clone();
        if !jobs::insert_queued(&mut tx, &id, &input).await? {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "The queue is full.".into(),
            ));
        }
        ids.push(id);
    }
    tx.commit().await?;
    app.0
        .database
        .audit("comparison.prepared", &ids[0], &ids[1])
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"baseline":ids[0],"target":ids[1],"baselineRef":before,"targetRef":after})),
    ))
}

async fn previous(State(app): State<App>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let previous: Option<Uuid> = sqlx::query_scalar(
        "SELECT s.id FROM scan_directory d JOIN scans current USING(id,queued_at)
         JOIN scans s USING(reference,platform)
         WHERE d.id=$1 AND current.status='completed' AND s.status='completed'
           AND (s.finished_at,s.id)<(current.finished_at,current.id)
         ORDER BY s.finished_at DESC NULLS LAST,s.id DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&app.0.database.primary)
    .await?;
    Ok(Json(json!({"id":previous})))
}

pub async fn report(
    app: &App,
    detail: &crate::store::ScanDetail,
    trivy_only: bool,
) -> ApiResult<(crate::domain::Report, Vec<String>)> {
    let unavailable = || {
        ApiError::bad("Both scans need complete vulnerability observations to compare detections.")
    };
    let saved = detail.report.as_ref().ok_or_else(unavailable)?;
    if saved.observation_complete == Some(false) {
        return Err(unavailable());
    }
    let id = crate::key(&detail.scan.id)?;
    let (scanners, failed): (Option<String>, bool) = sqlx::query_as(
        "SELECT s.scanner,EXISTS (
            SELECT FROM scan_activity a WHERE a.scan_id=d.id AND right(a.step,7)='_failed'
            AND a.lease_id=(SELECT lease_id FROM scan_activity WHERE scan_id=d.id ORDER BY id DESC LIMIT 1))
         FROM scan_directory d JOIN scans s USING(id,queued_at) WHERE d.id=$1",
    ).bind(id).fetch_one(&app.0.database.primary).await?;
    let engines_from_record = scanners.as_deref().unwrap_or("").split(", ");
    let mut engines: Vec<String> = engines_from_record
        .filter(|name| crate::discrepancies::SCANNERS.contains(name))
        .map(str::to_owned)
        .collect();
    engines.sort();
    if failed || (engines.is_empty() && detail.scan.source != "import") {
        return Err(unavailable());
    }
    if trivy_only || saved.observation_complete.is_none() {
        // Legacy aggregate finding keys may include other scans of the same digest.
        if !trivy_only && detail.scan.source != "import" && engines != ["trivy"] {
            return Err(ApiError::bad(
                "This older scan has no complete scan-specific finding record. Run a new scan to compare detections.",
            ));
        }
        let raw = crate::artifacts::trivy(app, &detail.scan.id)
            .await?
            .ok_or_else(unavailable)?;
        let (mut parsed, os_vulnerability_results) =
            crate::domain::Report::parse_trivy(&raw).map_err(ApiError::bad)?;
        if parsed.observation_complete != Some(true) || (trivy_only && !os_vulnerability_results) {
            return Err(unavailable());
        }
        parsed.digest = saved.digest.clone();
        return Ok((parsed, vec!["trivy".into()]));
    }
    if detail.scan.source == "import" && engines.is_empty() {
        engines.push("trivy".into());
    }
    Ok((saved.clone(), engines))
}

pub async fn issues(app: &App, scan: &str) -> ApiResult<Value> {
    Ok(sqlx::query_scalar(
        "WITH scan AS (
            SELECT s.repository_id,s.digest_id,s.reference,s.platform,d.observed_order,d.scan_no,s.observation_complete
            FROM scan_directory d JOIN scans s USING(id,queued_at) WHERE d.id=$1
         ), relevant AS (
            SELECT t.advisory_id FROM scan JOIN image_finding_tracking t USING(repository_id,digest_id,reference,platform) WHERE t.issue_url IS NOT NULL
            UNION
            SELECT k.advisory_id FROM scan s
            CROSS JOIN LATERAL observed_findings(s.digest_id,s.observed_order,s.scan_no,s.observation_complete IS NOT NULL) k
            JOIN advisory_issue_links g ON g.advisory_id=k.advisory_id
         )
         SELECT coalesce(jsonb_object_agg(a.external_id,jsonb_build_object('tracker',coalesce(t.tracker,g.tracker),
            'url',coalesce(t.issue_url,g.issue_url),'key',coalesce(t.issue_key,g.issue_key))),'{}'::jsonb)
         FROM scan s CROSS JOIN relevant k JOIN advisories a ON a.id=k.advisory_id
         LEFT JOIN image_finding_tracking t ON (t.repository_id,t.digest_id,t.reference,t.platform,t.advisory_id)
            =(s.repository_id,s.digest_id,s.reference,s.platform,a.id)
         LEFT JOIN advisory_issue_links g ON g.advisory_id=a.id",
    ).bind(crate::key(scan)?).fetch_one(&app.0.database.primary).await?)
}
