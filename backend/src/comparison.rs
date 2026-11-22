use crate::{
    ApiError, ApiResult, App, ImageReference, ImageTarget, ScanInput, image_target, images, jobs,
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};

use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

pub fn routes() -> Router<App> {
    Router::new().route("/compare/plan", post(plan))
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
