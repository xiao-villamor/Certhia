use crate::{ApiError, ApiResult, App, ImageTarget};
use anyhow::Result;
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    routing::{get, put},
};

use serde::Deserialize;
use serde_json::{Value, json};
use std::{convert::Infallible, time::Duration};

const DEFAULT_SCANNER: &str = "trivy";

pub fn routes() -> Router<App> {
    Router::new()
        .route("/scanners/available", get(available))
        .route("/settings/scanners", put(save_defaults))
        .route("/scans/{id}/progress", get(progress))
        .route("/scans/{id}/events", get(events))
}

fn engines() -> Vec<&'static str> {
    crate::artifacts::TOOLS
        .iter()
        .copied()
        .filter(|tool| crate::scanner::installed(tool))
        .collect()
}

async fn defaults(app: &App) -> Result<Option<Vec<String>>> {
    let stored = sqlx::query_scalar!("SELECT value FROM settings WHERE key='scan_engines'")
        .fetch_optional(&app.0.database.primary)
        .await?;
    Ok(stored.map(serde_json::from_value).transpose()?)
}

async fn available(State(app): State<App>) -> ApiResult<Json<Value>> {
    let installed = engines();
    Ok(Json(json!({
        "registry": installed,
        "local": installed,
        "defaults": defaults(&app).await?,
    })))
}

#[derive(Deserialize)]
struct ScannerDefaults {
    scanners: Vec<String>,
}

async fn save_defaults(
    State(app): State<App>,
    Json(input): Json<ScannerDefaults>,
) -> ApiResult<StatusCode> {
    let (scanners, _) = validate(Some(input.scanners), None)?;
    if scanners.is_empty() {
        sqlx::query!("DELETE FROM settings WHERE key='scan_engines'")
            .execute(&app.0.database.primary)
            .await?;
    } else {
        sqlx::query!(
            "INSERT INTO settings(key,value) VALUES('scan_engines',$1)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            json!(scanners)
        )
        .execute(&app.0.database.primary)
        .await?;
    }
    app.0
        .database
        .audit(
            "settings.scanners.updated",
            "instance",
            &scanners.join(", "),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn effective_scanners(app: &App, job: &crate::store::Job) -> Result<Vec<String>> {
    let requested = scanners(app, &job.id).await?;
    if !requested.is_empty() {
        return Ok(requested);
    }
    let mut configured = defaults(app).await?.unwrap_or_default();
    let installed = engines();
    configured.retain(|engine| installed.contains(&engine.as_str()));
    if configured.is_empty() {
        configured.push(DEFAULT_SCANNER.into());
    }
    Ok(configured)
}

pub fn validate(
    requested: Option<Vec<String>>,
    priority: Option<i32>,
) -> ApiResult<(Vec<String>, i32)> {
    let priority = priority.unwrap_or_default();
    if !(-10..=10).contains(&priority) {
        return Err(ApiError::bad("Priority must be between −10 and 10."));
    }
    let allowed = engines();
    let mut scanners = Vec::new();
    if let Some(requested) = requested {
        for scanner in requested {
            if !allowed.contains(&scanner.as_str()) {
                return Err(ApiError::bad(format!(
                    "Scanner {scanner} is not available for this source."
                )));
            }
            if !scanners.contains(&scanner) {
                scanners.push(scanner);
            }
        }
    }
    Ok((scanners, priority))
}

pub async fn enqueue(app: &App, input: &ImageTarget) -> Result<Option<String>> {
    let id = uuid::Uuid::now_v7().to_string();
    Ok(enqueue_with_id(app, &id, input).await?.then_some(id))
}

pub async fn enqueue_with_id(app: &App, id: &str, input: &ImageTarget) -> Result<bool> {
    let mut tx = app.0.database.primary.begin().await?;
    let inserted = insert_queued(&mut tx, id, input).await?;
    tx.commit().await?;
    Ok(inserted)
}

pub async fn insert_queued(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
    input: &ImageTarget,
) -> Result<bool> {
    // Preserve the queue-capacity contract when multiple producers submit batches.
    sqlx::query("SELECT pg_advisory_xact_lock(192387115)")
        .execute(&mut **tx)
        .await?;
    let full = sqlx::query_scalar!(r#"SELECT count(*)>=50 AS "full!" FROM scan_jobs"#)
        .fetch_one(&mut **tx)
        .await?;
    if full {
        return Ok(false);
    }
    sqlx::query!(
        "SELECT enqueue_scan($1,$2,$3,$4,$5,$6,$7)",
        uuid::Uuid::parse_str(id)?,
        input.reference,
        input.platform,
        input.source,
        input
            .registry_id
            .as_deref()
            .map(uuid::Uuid::parse_str)
            .transpose()?,
        &input.scanners,
        input.priority
    )
    .execute(&mut **tx)
    .await?;
    Ok(true)
}

pub async fn scanners(app: &App, id: &str) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar!(
        "SELECT s.scanners FROM scans s JOIN scan_directory d USING(id,queued_at) WHERE d.id=$1",
        uuid::Uuid::parse_str(id)?
    )
    .fetch_optional(&app.0.database.primary)
    .await?
    .unwrap_or_default())
}

#[derive(Clone, Copy)]
pub struct Activity<'a> {
    pub db: &'a crate::postgres::Database,
    pub lease: crate::ingest::Lease,
}
impl Activity<'_> {
    pub async fn record(self, step: &str, title: &str, detail: &str) {
        if let Err(error) = sqlx::query!(
            "SELECT record_scan_progress($1,$2,$3,$4,$5,$6)",
            self.lease.scan,
            self.lease.token,
            self.lease.owner,
            step,
            title,
            detail
        )
        .fetch_one(&self.db.primary)
        .await
        {
            tracing::warn!(%error,"Could not record scan activity");
        }
    }
}

pub async fn claim(
    app: &App,
    owner: uuid::Uuid,
    sources: &[String],
) -> Result<Option<crate::ingest::Lease>> {
    let row: Option<(uuid::Uuid, uuid::Uuid)> =
        sqlx::query_as("SELECT scan_id,lease_id FROM claim_scan($1,$2)")
            .bind(owner)
            .bind(sources)
            .fetch_optional(&app.0.database.primary)
            .await?;
    Ok(row.map(|(scan, token)| crate::ingest::Lease { scan, token, owner }))
}

pub async fn heartbeat(app: &App, lease: crate::ingest::Lease) -> Result<bool> {
    Ok(sqlx::query_scalar!(
        r#"SELECT renew_scan($1,$2,$3) AS "renewed!""#,
        lease.scan,
        lease.token,
        lease.owner
    )
    .fetch_one(&app.0.database.primary)
    .await?)
}

pub async fn listener(app: App) {
    loop {
        let result: Result<()> = async {
            let mut conn =
                sqlx::postgres::PgListener::connect(&std::env::var("DATABASE_URL")?).await?;
            conn.listen_all(["certhia_work", "certhia_activity"])
                .await?;
            app.0.work.notify_waiters();
            let _ = app.0.progress.send(String::new());
            while let Some(event) = conn.try_recv().await? {
                if event.channel() == "certhia_work" {
                    app.0.work.notify_waiters();
                } else {
                    let _ = app.0.progress.send(event.payload().to_owned());
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(%error,"PostgreSQL listener disconnected");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn summary(app: &App, id: &str) -> ApiResult<Value> {
    let key = uuid::Uuid::parse_str(id).map_err(|_| ApiError::missing("Scan not found."))?;
    let row=sqlx::query!(r#"SELECT s.status,s.error,s.started_at,
        CASE WHEN s.status='queued' THEN 1+(SELECT count(*) FROM scan_jobs q WHERE q.lease_id IS NULL
            AND (-q.priority,q.queued_at,q.scan_id)<(-s.priority,s.queued_at,s.id)) ELSE 0 END AS "position!"
        FROM scans s JOIN scan_directory d USING(id,queued_at) WHERE d.id=$1"#,key)
        .fetch_optional(&app.0.database.primary).await?.ok_or_else(||ApiError::missing("Scan not found."))?;
    let entries = sqlx::query!(
        "SELECT step,title,detail,at FROM scan_activity WHERE scan_id=$1 AND lease_id=
        (SELECT lease_id FROM scan_activity WHERE scan_id=$1 ORDER BY id DESC LIMIT 1) ORDER BY id",
        key
    )
    .fetch_all(&app.0.database.primary)
    .await?;
    let activity: Vec<_> = entries
        .into_iter()
        .map(|r| json!({"step":r.step,"title":r.title,"detail":r.detail,"at":r.at}))
        .collect();
    Ok(
        json!({"id":id,"status":row.status,"error":row.error,"queuePosition":row.position,
        "progress":match row.status.as_str(){"queued"=>0,"running"=>25,_=>100},"startedAt":row.started_at,"activity":activity}),
    )
}
async fn progress(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    Ok(Json(summary(&app, &id).await?))
}

async fn events(
    State(app): State<App>,
    Path(id): Path<String>,
    Extension(session): Extension<crate::auth::Session>,
) -> ApiResult<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>> {
    let rx = app.0.progress.subscribe();
    let first = summary(&app, &id).await?;
    let recheck = Duration::from_secs(15);
    let clock = tokio::time::interval_at(tokio::time::Instant::now() + recheck, recheck);
    let stream = futures_util::stream::unfold(
        (app, id, rx, Some(first), false, session, clock),
        |(app, id, mut rx, first, done, session, mut clock)| async move {
            if done {
                return None;
            }
            let value = match first {
                Some(v) => v,
                None => {
                    loop {
                        tokio::select! {
                            biased;
                            _ = clock.tick() => {
                                if !session.is_active(&app.0.database.primary).await.unwrap_or(false) {
                                    return None;
                                }
                            }
                            event = rx.recv() => match event {
                                Ok(key) if key == id || key.is_empty() => break,
                                Ok(_) => continue,
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => break,
                                Err(_) => return None,
                            }
                        }
                    }
                    summary(&app, &id)
                        .await
                        .unwrap_or_else(|_| json!({"id":id,"status":"removed","progress":100}))
                }
            };
            let done = !matches!(value["status"].as_str(), Some("queued" | "running"));
            Some((
                Ok(Event::default().event("progress").data(value.to_string())),
                (app, id, rx, None, done, session, clock),
            ))
        },
    );
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
