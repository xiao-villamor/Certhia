use crate::{ApiError, ApiResult, App};
use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get},
};

use serde::Serialize;
use serde_json::{Value, json};

use uuid::Uuid;

pub fn routes() -> Router<App> {
    Router::new()
        .route("/image-watches", get(list))
        .route("/image-watches/{id}", delete(remove))
        .route("/scans/{id}/watch", get(for_scan).put(enable))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Watch {
    id: Uuid,
    reference: String,
    platform: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn list(
    State(app): State<App>,
    axum::extract::Query(q): axum::extract::Query<WatchPage>,
) -> ApiResult<Json<Value>> {
    let limit = crate::IdPage {
        cursor: None,
        limit: q.limit,
    }
    .limit()?;
    let mut watches = sqlx::query_as!(
        Watch,
        "SELECT * FROM image_watches WHERE $1::uuid IS NULL OR id<$1 ORDER BY id DESC LIMIT $2",
        q.cursor,
        limit + 1
    )
    .fetch_all(&app.0.database.primary)
    .await?;
    let mut alerts=sqlx::query_scalar!(r#"SELECT jsonb_build_object('id',a.id,'reference',w.reference,'platform',w.platform,'scanId',s.id,
        'advisories',ARRAY(SELECT v.external_id FROM watch_alert_advisories aa JOIN advisories v ON v.id=aa.advisory_id WHERE aa.alert_id=a.id ORDER BY v.external_id),
        'createdAt',a.created_at,'delivery',CASE WHEN a.delivered_at IS NOT NULL THEN 'delivered' WHEN a.next_attempt IS NULL THEN 'failed' ELSE 'pending' END,
        'error',a.error) AS "entry!" FROM watch_alerts a JOIN image_watches w ON w.id=a.watch_id JOIN scan_directory d ON d.id=a.scan_id
        LEFT JOIN scans s ON s.id=d.id AND s.queued_at=d.queued_at WHERE $1::bigint IS NULL OR a.id<$1 ORDER BY a.id DESC LIMIT $2"#,q.alert_cursor,limit+1).fetch_all(&app.0.database.primary).await?;
    let next = if watches.len() > limit as usize {
        watches.pop();
        watches.last().map(|r| r.id)
    } else {
        None
    };
    let next_alert = if alerts.len() > limit as usize {
        alerts.pop();
        alerts.last().map(|r| &r["id"])
    } else {
        None
    };
    Ok(Json(
        json!({"watches":watches,"alerts":alerts,"nextCursor":next,"nextAlertCursor":next_alert}),
    ))
}
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WatchPage {
    cursor: Option<Uuid>,
    alert_cursor: Option<i64>,
    limit: Option<i64>,
}

async fn for_scan(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Json<Option<Watch>>> {
    let scan = app
        .0
        .database
        .replay(&id)
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    Ok(Json(
        sqlx::query_as!(
            Watch,
            "SELECT * FROM image_watches WHERE reference=$1 AND platform=$2",
            scan.reference,
            scan.platform
        )
        .fetch_optional(&app.0.database.primary)
        .await?,
    ))
}
async fn enable(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Watch>> {
    let mut tx = app.0.database.primary.begin().await?;
    let row=sqlx::query!("SELECT reference,platform,status FROM scan_directory d JOIN scans s USING(id,queued_at) WHERE d.id=$1",crate::key(&id)?).fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::missing("Scan not found."))?;
    if row.status != "completed" {
        return Err(ApiError::bad("Complete a scan before watching this image."));
    }
    let new_id = Uuid::now_v7();
    let watch=sqlx::query_as!(Watch,"INSERT INTO image_watches VALUES($1,$2,$3,now()) ON CONFLICT(reference,platform) DO UPDATE SET platform=excluded.platform RETURNING *",
        new_id,row.reference,row.platform).fetch_one(&mut *tx).await?;
    if watch.id == new_id {
        sqlx::query("INSERT INTO watch_seen SELECT DISTINCT $1::uuid,k.advisory_id
            FROM latest_completed_scans s JOIN scan_directory d USING(id,queued_at)
            CROSS JOIN LATERAL observed_findings(s.digest_id,d.observed_order,d.scan_no,s.observation_complete IS NOT NULL) k
            WHERE s.reference=$2 AND s.platform=$3")
            .bind(new_id).bind(&row.reference).bind(&row.platform).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    app.0
        .database
        .audit("image_watch.enabled", &watch.id.to_string(), &row.reference)
        .await?;
    Ok(Json(watch))
}
async fn remove(State(app): State<App>, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    sqlx::query!("DELETE FROM image_watches WHERE id=$1", id)
        .execute(&app.0.database.primary)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
pub async fn record(
    tx: &mut sqlx::PgConnection,
    scan_id: Uuid,
    scan_no: i64,
    reference: &str,
    platform: &str,
) -> Result<()> {
    sqlx::query("WITH added AS (
        INSERT INTO watch_seen SELECT DISTINCT w.id,f.advisory_id FROM image_watches w JOIN scan_observed_findings f ON f.scan_no=$2
        WHERE w.reference=$3 AND w.platform=$4 ON CONFLICT DO NOTHING RETURNING watch_id,advisory_id
        ),alert AS(INSERT INTO watch_alerts(watch_id,scan_id,next_attempt) SELECT DISTINCT watch_id,$1::uuid,now() FROM added RETURNING id,watch_id)
        INSERT INTO watch_alert_advisories SELECT alert.id,added.advisory_id FROM added JOIN alert USING(watch_id)").bind(scan_id).bind(scan_no).bind(reference).bind(platform).execute(tx).await?;
    Ok(())
}
pub async fn deliver_pending(app: &App) -> Result<()> {
    let item=sqlx::query!(r#"WITH claimed AS(UPDATE watch_alerts SET next_attempt=now()+interval '60 seconds' WHERE id=(
        SELECT id FROM watch_alerts WHERE next_attempt<=now() ORDER BY next_attempt,id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *)
        SELECT a.id,w.reference,w.platform,a.scan_id,a.next_attempt,a.attempts,ARRAY(SELECT v.external_id FROM watch_alert_advisories aa JOIN advisories v
        ON v.id=aa.advisory_id WHERE aa.alert_id=a.id ORDER BY v.external_id) AS "advisories!" FROM claimed a JOIN image_watches w ON w.id=a.watch_id"#)
        .fetch_optional(&app.0.database.primary).await?;
    let Some(item) = item else {
        return Ok(());
    };
    let preview = item
        .advisories
        .iter()
        .take(12)
        .map(|id| {
            id.chars()
                .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | ':'))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(", ");
    let text = format!(
        "{} new vulnerabilities detected in {} ({}). Scan {}. {}{}",
        item.advisories.len(),
        item.reference,
        item.platform,
        item.scan_id,
        preview,
        if item.advisories.len() > 12 {
            "…"
        } else {
            ""
        },
    );
    match crate::automation::send_alert(app, &text).await {
        Ok(false) => {}
        Ok(true) => {
            sqlx::query!("UPDATE watch_alerts SET delivered_at=now(),next_attempt=NULL,error=NULL WHERE id=$1 AND next_attempt=$2",item.id,item.next_attempt).execute(&app.0.database.primary).await?;
        }
        Err(error) => {
            let retry = [30i32, 120, 600, 1800].get(item.attempts as usize).copied();
            sqlx::query!("UPDATE watch_alerts SET attempts=attempts+1,next_attempt=now()+$3::integer * interval '1 second',error=$4 WHERE id=$1 AND next_attempt=$2",item.id,item.next_attempt,retry,error.to_string()).execute(&app.0.database.primary).await?;
        }
    }
    Ok(())
}
