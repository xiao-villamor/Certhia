use crate::{
    ApiError, ApiResult, App, ImageReference, ImageTarget, ScanInput,
    discrepancies::SCANNERS,
    domain::{Finding, Report, merge_findings},
    image_target, images, jobs,
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
        .route("/scans/{id}/previous-version", get(previous_version))
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

async fn previous_version(State(app): State<App>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let suggested: Option<Uuid> = sqlx::query_scalar(
        "SELECT s.id FROM scan_directory d JOIN scans current USING(id,queued_at)
         JOIN scans s ON s.repository_id=current.repository_id AND s.platform=current.platform
         WHERE d.id=$1 AND current.status='completed' AND s.status='completed'
           AND (s.finished_at,s.id)<(current.finished_at,current.id)
         ORDER BY (s.reference<>current.reference) DESC,
           EXISTS (SELECT 1 FROM unnest($2::text[]) tool
                   WHERE tool=ANY(string_to_array(s.scanner,', ')) AND tool=ANY(string_to_array(current.scanner,', '))) DESC,
           s.finished_at DESC,s.id DESC LIMIT 1",
    )
    .bind(id)
    .bind(&SCANNERS[..])
    .fetch_optional(&app.0.database.primary)
    .await?;
    Ok(Json(json!({"id":suggested})))
}

pub fn engines(report: &Report, source: &str) -> Vec<&'static str> {
    let mut tools: Vec<_> = SCANNERS
        .into_iter()
        .filter(|tool| report.scanners.iter().any(|recorded| recorded == tool))
        .collect();
    if tools.is_empty() && source == "import" {
        tools.push("trivy");
    }
    tools.sort_unstable();
    tools
}

pub async fn align_findings(
    app: &App,
    baseline: (&str, &mut Report, &[&'static str]),
    target: (&str, &mut Report, &[&'static str]),
) -> Vec<&'static str> {
    let (before_id, before, before_tools) = baseline;
    let (after_id, after, after_tools) = target;
    if before_tools == after_tools
        && !before_tools.is_empty()
        && before.observation_complete == Some(true)
        && after.observation_complete == Some(true)
    {
        return before_tools.to_vec();
    }

    let mut comparable = Vec::new();
    let mut before_findings = Vec::new();
    let mut after_findings = Vec::new();
    // Merged findings may carry severity and fix data from an engine that only ran on one side.
    for &tool in before_tools
        .iter()
        .filter(|tool| after_tools.contains(tool))
    {
        let (baseline, target) = tokio::join!(
            engine_findings(app, before_id, before, before_tools, tool),
            engine_findings(app, after_id, after, after_tools, tool)
        );
        if let (Some(baseline), Some(target)) = (baseline, target) {
            comparable.push(tool);
            before_findings.extend(baseline);
            after_findings.extend(target);
        }
    }
    before.findings = merge_findings(before_findings.into_iter());
    after.findings = merge_findings(after_findings.into_iter());
    comparable
}

async fn engine_findings(
    app: &App,
    id: &str,
    saved: &Report,
    tools: &[&str],
    tool: &'static str,
) -> Option<Vec<Finding>> {
    if tools == [tool] && saved.observation_complete == Some(true) {
        return Some(saved.findings.clone());
    }
    let findings = async {
        let raw = if tool == "trivy" {
            crate::artifacts::trivy(app, id).await?
        } else {
            crate::artifacts::report(app, id, tool).await?
        };
        let Some(raw) = raw else {
            return Ok(None);
        };
        tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let report = if tool == "trivy" {
                Report::from_trivy(&raw)?
            } else {
                crate::native_scanners::parse(tool, &mut serde_json::from_slice(&raw)?, "")?
            };
            Ok((report.observation_complete != Some(false)).then_some(report.findings))
        })
        .await?
    }
    .await;
    match findings {
        Ok(findings) => findings,
        Err(error) => {
            tracing::warn!(scan_id = id, scanner = tool, %error, "Could not read comparison findings");
            None
        }
    }
}

pub async fn publication_report(
    app: &App,
    scan: &crate::store::Scan,
    saved: &Report,
) -> ApiResult<Report> {
    let unavailable = || {
        ApiError::bad("Both scans need complete vulnerability observations to compare detections.")
    };
    if saved.observation_complete == Some(false) {
        return Err(unavailable());
    }
    let id = crate::key(&scan.id)?;
    let failed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM scan_activity a WHERE a.scan_id=$1 AND right(a.step,7)='_failed'
            AND a.lease_id=(SELECT lease_id FROM scan_activity WHERE scan_id=$1 ORDER BY id DESC LIMIT 1))",
    ).bind(id).fetch_one(&app.0.database.primary).await?;
    if failed || engines(saved, &scan.source).is_empty() {
        return Err(unavailable());
    }
    let raw = crate::artifacts::trivy(app, &scan.id)
        .await?
        .ok_or_else(unavailable)?;
    let (mut parsed, os_vulnerability_results) =
        tokio::task::spawn_blocking(move || Report::parse_trivy(&raw))
            .await
            .map_err(anyhow::Error::from)?
            .map_err(ApiError::bad)?;
    if parsed.observation_complete != Some(true) || !os_vulnerability_results {
        return Err(unavailable());
    }
    parsed.digest = saved.digest.clone();
    Ok(parsed)
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
