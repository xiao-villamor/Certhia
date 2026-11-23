use crate::issue_trackers::{self, IssueSelection};
use crate::{ApiError, ApiResult, App, ScanInput, image_target};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};

use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const CANCELLED: &str = "Scan cancelled";
pub const FINDING_STATUSES: &[&str] = &[
    "open",
    "accepted_risk",
    "false_positive",
    "fixed",
    "will_not_fix",
    "in_progress",
];

pub fn routes() -> Router<App> {
    Router::new()
        .route("/scans/bulk", post(bulk).get(batches))
        .route("/scans/{id}/rescan", post(rescan))
        .route("/scans/{id}/retry-options", get(retry_options))
        .route("/scans/{id}/cancel", post(cancel))
        .route("/scans/{id}/report/{format}", get(crate::exports::download))
        .route(
            "/scans/{id}/classifications",
            get(classifications).put(classify),
        )
        .route("/images", get(images))
        .route("/images/delete", post(remove_images))
        .route("/vulnerabilities", get(vulnerabilities))
        .route("/library/packages", get(packages))
        .route("/audit-logs", get(events))
}

#[derive(Deserialize)]
struct BulkInput {
    scans: Vec<ScanInput>,
}

#[derive(Deserialize)]
struct Ids {
    ids: Vec<String>,
}

async fn bulk(
    State(app): State<App>,
    Json(input): Json<BulkInput>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    if !(1..=50).contains(&input.scans.len()) {
        return Err(ApiError::bad("Enter between 1 and 50 images."));
    }
    let mut inputs = Vec::with_capacity(input.scans.len());
    for scan in input.scans {
        inputs.push(image_target(&app, scan).await?);
    }
    let mut tx = app.0.database.primary.begin().await?;
    let batch_id = Uuid::now_v7().to_string();
    sqlx::query!(
        "INSERT INTO batches VALUES($1,now())",
        crate::key(&batch_id)?
    )
    .execute(&mut *tx)
    .await?;
    let mut ids = Vec::new();
    for input in inputs {
        let id = Uuid::now_v7();
        if !crate::jobs::insert_queued(&mut tx, &id.to_string(), &input).await? {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "The scan queue has insufficient space for this batch.".into(),
            ));
        }
        sqlx::query!(
            "INSERT INTO batch_scans VALUES($1,$2)",
            crate::key(&batch_id)?,
            id
        )
        .execute(&mut *tx)
        .await?;
        ids.push(id);
    }
    tx.commit().await?;
    app.0
        .database
        .audit("batch.queued", &batch_id, &format!("{} images", ids.len()))
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({ "id": batch_id, "scanIds": ids })),
    ))
}

async fn batches(
    State(app): State<App>,
    Query(page): Query<crate::IdPage>,
) -> ApiResult<crate::List<Value>> {
    let rows=sqlx::query!("SELECT b.id,b.created_at,count(s.id) AS total,count(*) FILTER(WHERE s.status NOT IN ('queued','running')) AS finished,
        count(*) FILTER(WHERE s.status='failed') AS failed FROM (SELECT * FROM batches WHERE $1::uuid IS NULL OR id<$1 ORDER BY id DESC LIMIT $2)b
        LEFT JOIN batch_scans bs ON b.id=bs.batch_id LEFT JOIN scan_directory d ON d.id=bs.scan_id LEFT JOIN scans s ON s.id=d.id AND s.queued_at=d.queued_at
        GROUP BY b.id,b.created_at ORDER BY b.id DESC",page.cursor,page.limit()?+1).fetch_all(&app.0.database.primary).await?;
    crate::page_rows(rows.into_iter().map(|r|json!({"id":r.id,"createdAt":r.created_at,"total":r.total,"finished":r.finished,"failed":r.failed})).collect(),page.limit()?,|v|v["id"].as_str().unwrap().to_owned())
}

async fn retry_options(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let previous = app
        .0
        .database
        .replay(&id)
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    let scanners = crate::jobs::scanners(&app, &id).await?;
    let priority = sqlx::query_scalar::<_, i32>(
        "SELECT s.priority FROM scan_directory d JOIN scans s USING(id,queued_at) WHERE d.id=$1",
    )
    .bind(crate::key(&id)?)
    .fetch_one(&app.0.database.primary)
    .await?;
    Ok(Json(json!({
        "reference":previous.reference,"platform":previous.platform,"registryId":previous.registry_id,
        "source":if previous.source=="import" { "registry" } else { &previous.source },
        "scanners":scanners,"priority":priority,
    })))
}

async fn rescan(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let previous = app
        .0
        .database
        .replay(&id)
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    if previous.source == "archive" {
        return Err(ApiError::bad("Upload the archive again to rescan it."));
    }
    let input = image_target(
        &app,
        ScanInput {
            scanners: Some(crate::jobs::scanners(&app, &id).await?),
            priority: None,
            reference: previous.reference,
            platform: previous.platform,
            registry_id: previous.registry_id,
            source: if previous.source == "import" {
                None
            } else {
                Some(previous.source)
            },
        },
    )
    .await?;
    let id = crate::jobs::enqueue(&app, &input).await?.ok_or_else(|| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "The scan queue is full.".into(),
        )
    })?;
    app.0
        .database
        .audit("scan.requeued", &id, &input.reference)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({ "id": id }))))
}

async fn cancel(State(app): State<App>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let mut tx = app.0.database.primary.begin().await?;
    let queued_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("DELETE FROM scan_jobs WHERE scan_id=$1 RETURNING queued_at")
            .bind(crate::key(&id)?)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(queued_at) = queued_at else {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "Only queued or running scans can be cancelled.".into(),
        ));
    };
    sqlx::query!("UPDATE scans SET status='cancelled',error=$3,finished_at=now() WHERE id=$1 AND queued_at=$2",crate::key(&id)?,queued_at,CANCELLED).execute(&mut *tx).await?;
    sqlx::query("SELECT pg_notify('certhia_activity',$1),pg_notify('certhia_work','')")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if app
        .0
        .database
        .replay(&id)
        .await?
        .is_some_and(|scan| scan.source == "archive")
    {
        let _ = tokio::fs::remove_file(app.0.data.join("archives").join(&id)).await;
    }
    app.0.database.audit("scan.cancelled", &id, "").await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_images(State(app): State<App>, Json(body): Json<Ids>) -> ApiResult<Json<Value>> {
    if !(1..=200).contains(&body.ids.len()) {
        return Err(ApiError::bad("Choose between 1 and 200 scans."));
    }
    let mut removed = 0;
    for id in body.ids {
        if sqlx::query!("DELETE FROM scans s USING scan_directory d WHERE d.id=$1 AND s.id=d.id AND s.queued_at=d.queued_at AND s.status NOT IN ('queued','running')",crate::key(&id)?).execute(&app.0.database.primary).await?.rows_affected()>0 {
            app.0.database.audit("scan.deleted", &id, "").await?;
            let _ = tokio::fs::remove_file(app.0.data.join("archives").join(&id)).await;
            removed += 1;
        }
    }
    Ok(Json(json!({ "removed": removed })))
}

pub fn repository(reference: &str) -> &str {
    let name = reference.split('@').next().unwrap_or(reference);
    match (name.rfind('/'), name.rfind(':')) {
        (Some(slash), Some(colon)) if colon > slash => &name[..colon],
        (None, Some(colon)) => &name[..colon],
        _ => name,
    }
}

async fn images(
    State(app): State<App>,
    Query(q): Query<crate::ScanPage>,
) -> ApiResult<(axum::http::HeaderMap, Json<Value>)> {
    let limit = q.limit()?;
    let rows = app
        .0
        .database
        .scan_page(
            q.cursor,
            limit + 1,
            q.q.as_deref(),
            q.status.as_deref(),
            q.repository.as_deref(),
            q.platform.as_deref(),
        )
        .await?;
    let (headers, Json(rows)) = crate::page_rows(rows, limit, |r| r.id.clone())?;
    let mut groups = BTreeMap::<String, Vec<crate::store::Scan>>::new();
    for scan in rows {
        groups
            .entry(repository(&scan.reference).to_owned())
            .or_default()
            .push(scan);
    }
    Ok((headers, Json(json!(groups))))
}

async fn classifications(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<ClassificationPage>,
) -> ApiResult<crate::List<Value>> {
    let limit = crate::IdPage {
        cursor: None,
        limit: q.limit,
    }
    .limit()?;
    let rows = sqlx::query_scalar::<_, Value>(r#"
        WITH scan AS (
            SELECT s.repository_id,s.digest_id,s.reference,s.platform,d.observed_order,d.scan_no,s.observation_complete
            FROM scan_directory d JOIN scans s USING(id,queued_at) WHERE d.id=$1
        ), tracked AS (
            SELECT t.advisory_id FROM scan JOIN image_finding_tracking t USING(repository_id,digest_id,reference,platform)
            UNION
            SELECT k.advisory_id FROM scan s
            CROSS JOIN LATERAL observed_findings(s.digest_id,s.observed_order,s.scan_no,s.observation_complete IS NOT NULL) k
            WHERE EXISTS (SELECT FROM advisory_issue_links g WHERE g.advisory_id=k.advisory_id)
                OR EXISTS (SELECT FROM active_finding_exception(s.repository_id,k.advisory_id,s.platform,s.reference))
        )
        SELECT jsonb_build_object('finding',a.external_id,'status',coalesce(t.status,'open'),'note',coalesce(t.note,''),
            'updatedAt',t.updated_at,'issue',CASE
                WHEN t.tracker IS NOT NULL THEN jsonb_strip_nulls(jsonb_build_object('tracker',t.tracker,'trackerId',t.tracker_id,'url',t.issue_url,'key',t.issue_key))
                WHEN g.tracker IS NOT NULL THEN jsonb_strip_nulls(jsonb_build_object('tracker',g.tracker,'trackerId',g.tracker_id,'url',g.issue_url,'key',g.issue_key,'scope','advisory'))
            END) || CASE WHEN e.reason IS NOT NULL THEN
                jsonb_build_object('exception',jsonb_build_object('scope',CASE WHEN e.reference='' THEN 'repository' ELSE 'reference' END,
                    'reason',e.reason,'expiresAt',e.expires_at))
                ELSE '{}'::jsonb END
        FROM scan s CROSS JOIN tracked k JOIN advisories a ON a.id=k.advisory_id
        LEFT JOIN image_finding_tracking t ON (t.repository_id,t.digest_id,t.reference,t.platform,t.advisory_id)
            =(s.repository_id,s.digest_id,s.reference,s.platform,a.id)
        LEFT JOIN advisory_issue_links g ON g.advisory_id=a.id
        LEFT JOIN LATERAL active_finding_exception(s.repository_id,a.id,s.platform,s.reference) e ON true
        WHERE a.external_id>coalesce($2,'') AND ($4::text IS NULL OR a.external_id=$4)
        ORDER BY a.external_id LIMIT $3"#)
        .bind(crate::key(&id)?).bind(q.cursor).bind(limit+1).bind(q.finding)
        .fetch_all(&app.0.database.primary).await?;
    crate::page_rows(rows, limit, |r| r["finding"].as_str().unwrap().to_string())
}

#[derive(Deserialize)]
struct ClassificationPage {
    cursor: Option<String>,
    limit: Option<i64>,
    finding: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClassificationInput {
    finding: String,
    status: String,
    #[serde(default)]
    note: String,
    #[serde(default, deserialize_with = "deserialize_issue_update")]
    issue: Option<Option<IssueSelection>>,
    #[serde(default)]
    issue_scope: IssueScope,
    exception_edit: Option<ExceptionEdit>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum IssueScope {
    #[default]
    Image,
    Advisory,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExceptionScope {
    Reference,
    Repository,
}

impl ExceptionScope {
    fn reference<'a>(&self, reference: &'a str) -> &'a str {
        match self {
            Self::Reference => reference,
            Self::Repository => "",
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Reference => "reference",
            Self::Repository => "repository",
        }
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum ExceptionEdit {
    Set {
        scope: ExceptionScope,
        reason: String,
        expires_at: chrono::DateTime<chrono::Utc>,
    },
    Revoke {
        scope: ExceptionScope,
    },
}

fn deserialize_issue_update<'de, D>(
    deserializer: D,
) -> Result<Option<Option<IssueSelection>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<IssueSelection>::deserialize(deserializer).map(Some)
}

async fn classify(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<ClassificationInput>,
) -> ApiResult<StatusCode> {
    if !FINDING_STATUSES.contains(&input.status.as_str())
        || input.finding.len() > 150
        || input.note.len() > 4000
    {
        return Err(ApiError::bad("Enter a valid classification and note."));
    }
    let mut tx = app.0.database.primary.begin().await?;
    let scan_id = crate::key(&id)?;
    let (reference, platform, repository, digest, advisory) = sqlx::query_as::<_, (String, String, i64, i64, i32)>(r#"SELECT s.reference,s.platform,s.repository_id,s.digest_id,a.id
        FROM scan_directory d JOIN scans s USING(id,queued_at)
        JOIN LATERAL observed_findings(s.digest_id,d.observed_order,d.scan_no,s.observation_complete IS NOT NULL) k ON true
        JOIN advisories a ON a.id=k.advisory_id
        WHERE d.id=$1 AND s.status='completed' AND a.external_id=$2 LIMIT 1"#).bind(scan_id).bind(&input.finding).fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::missing("Finding not present in this report."))?;
    let exception_event = match input.exception_edit {
        Some(ExceptionEdit::Set {
            scope,
            reason,
            expires_at,
        }) => {
            let reason = reason.trim();
            if reason.is_empty() || reason.len() > 4000 || expires_at <= chrono::Utc::now() {
                return Err(ApiError::bad(
                    "Enter a reason and a future expiry for the exception.",
                ));
            }
            sqlx::query("INSERT INTO finding_exceptions (repository_id,advisory_id,platform,reference,reason,expires_at)
                VALUES ($1,$2,$3,$4,$5,$6)
                ON CONFLICT(repository_id,advisory_id,platform,reference)
                DO UPDATE SET reason=excluded.reason,expires_at=excluded.expires_at")
                .bind(repository).bind(advisory).bind(&platform).bind(scope.reference(&reference))
                .bind(reason).bind(expires_at).execute(&mut *tx).await?;
            Some((
                "finding.exception_set",
                format!(
                    "{} · {} · {} · expires {}",
                    input.finding,
                    platform,
                    scope.label(),
                    expires_at
                ),
            ))
        }
        Some(ExceptionEdit::Revoke { scope }) => {
            let result = sqlx::query(
                "DELETE FROM finding_exceptions WHERE
                    repository_id=$1 AND advisory_id=$2 AND platform=$3 AND reference=$4",
            )
            .bind(repository)
            .bind(advisory)
            .bind(&platform)
            .bind(scope.reference(&reference))
            .execute(&mut *tx)
            .await?;
            (result.rows_affected() > 0).then(|| {
                (
                    "finding.exception_revoked",
                    format!("{} · {} · {}", input.finding, platform, scope.label()),
                )
            })
        }
        None => None,
    };
    let replace_issue = input.issue.is_some();
    let issue = match input.issue.flatten() {
        Some(selection) => Some(issue_trackers::resolve(&mut tx, selection).await?),
        None => None,
    };
    let tracker_id = issue
        .as_ref()
        .and_then(|link| link.tracker_id.as_deref())
        .map(crate::key)
        .transpose()?;
    let shared = matches!(input.issue_scope, IssueScope::Advisory);
    if shared && replace_issue {
        if let Some(link) = &issue {
            sqlx::query("INSERT INTO advisory_issue_links(advisory_id,tracker_id,tracker,issue_url,issue_key)
                VALUES($1,$2,$3,$4,$5) ON CONFLICT(advisory_id) DO UPDATE SET
                tracker_id=excluded.tracker_id,tracker=excluded.tracker,issue_url=excluded.issue_url,issue_key=excluded.issue_key")
                .bind(advisory).bind(tracker_id).bind(&link.tracker).bind(&link.url).bind(&link.key)
                .execute(&mut *tx).await?;
        } else {
            sqlx::query("DELETE FROM advisory_issue_links WHERE advisory_id=$1")
                .bind(advisory)
                .execute(&mut *tx)
                .await?;
        }
    }
    // Promoting a link clears the override on this image. Removing a shared link leaves image overrides intact.
    let replace_local = replace_issue && (!shared || issue.is_some());
    let local_issue = if shared { None } else { issue.as_ref() };
    let local_tracker_id = if shared { None } else { tracker_id };
    sqlx::query!("INSERT INTO image_finding_tracking AS existing
        (repository_id,digest_id,reference,platform,advisory_id,status,note,updated_at,tracker_id,tracker,issue_url,issue_key)
        VALUES($1,$2,$3,$4,$5,$6,$7,now(),$8,$9,$10,$11)
        ON CONFLICT(repository_id,digest_id,reference,platform,advisory_id) DO UPDATE SET
            status=excluded.status,note=excluded.note,updated_at=excluded.updated_at,
            tracker_id=CASE WHEN $12 THEN excluded.tracker_id ELSE existing.tracker_id END,
            tracker=CASE WHEN $12 THEN excluded.tracker ELSE existing.tracker END,
            issue_url=CASE WHEN $12 THEN excluded.issue_url ELSE existing.issue_url END,
            issue_key=CASE WHEN $12 THEN excluded.issue_key ELSE existing.issue_key END",
        repository,digest,reference,platform,advisory,input.status,input.note,
        local_tracker_id,local_issue.map(|link| link.tracker.as_str()),local_issue.map(|link| link.url.as_str()),
        local_issue.map(|link| link.key.as_str()),replace_local).execute(&mut *tx).await?;
    sqlx::query!("INSERT INTO vex_reviews VALUES($1,$2,$3,$4,now()) ON CONFLICT(scan_id,advisory_id) DO UPDATE SET status=excluded.status,note=excluded.note,reviewed_at=now()",scan_id,advisory,input.status,input.note).execute(&mut *tx).await?;
    tx.commit().await?;
    app.0
        .database
        .audit("finding.classified", &reference, &input.finding)
        .await?;
    if let Some((action, detail)) = exception_event {
        app.0.database.audit(action, &reference, &detail).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct LibraryFilter {
    package: Option<String>,
    advisory: Option<String>,
    q: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    linked: Option<bool>,
    ecosystems: Option<String>,
    fixable: Option<bool>,
    latest: Option<bool>,
    cursor: Option<String>,
    limit: Option<i64>,
}

#[derive(Default, Deserialize)]
struct LibraryCursor(i32, i64, i32, i64, #[serde(default)] Option<[String; 2]>);

async fn vulnerabilities(
    State(app): State<App>,
    Query(q): Query<LibraryFilter>,
) -> ApiResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let limit = crate::IdPage {
        cursor: None,
        limit: q.limit,
    }
    .limit()?;
    let cursor: LibraryCursor = q
        .cursor
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(ApiError::bad)?
        .unwrap_or_default();
    let (reference, platform) = cursor
        .4
        .map(|[reference, platform]| (reference, platform))
        .unzip();
    #[derive(sqlx::FromRow)]
    struct LibraryRow {
        aid: i32,
        digest_id: i64,
        pid: i32,
        repository_id: i64,
        id: String,
        ecosystem: String,
        package: String,
        installed: String,
        purl: Option<String>,
        fixed: String,
        severity: String,
        title: String,
        reference: String,
        platform: String,
        finished_at: Option<chrono::DateTime<chrono::Utc>>,
        scan: uuid::Uuid,
        digest: String,
        status: String,
        issue: Option<Value>,
        exception: Option<Value>,
    }
    let rows=sqlx::query_as::<_, LibraryRow>(r#"WITH scope AS (
          SELECT * FROM latest_completed_scans WHERE $14
          UNION ALL
          (SELECT DISTINCT ON (reference,platform,digest_id) * FROM scans
           WHERE NOT $14 AND status='completed'
           ORDER BY reference,platform,digest_id,finished_at DESC NULLS LAST,id DESC)
        )
        SELECT a.id AS aid,s.digest_id,p.id AS pid,s.repository_id,a.external_id AS id,e.name AS ecosystem,p.name AS package,p.version AS installed,p.purl,
        coalesce(v.version,'') AS fixed,upper(sev.name) AS severity,coalesce(k.title,'') AS title,
        s.reference,s.platform,s.finished_at,s.id AS scan,d.digest,coalesce(nullif(t.status,'open'),
            CASE WHEN efx.reason IS NOT NULL THEN 'excepted' ELSE 'open' END) AS status,
        CASE WHEN efx.reason IS NOT NULL THEN jsonb_build_object('scope',CASE WHEN efx.reference='' THEN 'repository' ELSE 'reference' END,
            'reason',efx.reason,'expiresAt',efx.expires_at) END AS exception,
        CASE WHEN t.tracker IS NOT NULL THEN jsonb_strip_nulls(jsonb_build_object('tracker',t.tracker,'trackerId',t.tracker_id,'url',t.issue_url,'key',t.issue_key))
        WHEN g.tracker IS NOT NULL THEN jsonb_strip_nulls(jsonb_build_object('tracker',g.tracker,'trackerId',g.tracker_id,'url',g.issue_url,'key',g.issue_key,'scope','advisory')) END AS issue
        FROM scope s JOIN scan_directory sd USING(id,queued_at) JOIN digests d ON d.id=s.digest_id
        CROSS JOIN LATERAL observed_findings(s.digest_id,sd.observed_order,sd.scan_no,s.observation_complete IS NOT NULL) k
        JOIN advisories a ON a.id=k.advisory_id JOIN packages p ON p.id=k.package_id JOIN ecosystems e ON e.id=p.ecosystem_id
        JOIN severities sev ON sev.id=k.severity_id LEFT JOIN fix_versions v ON v.id=k.fixed_in
        LEFT JOIN image_finding_tracking t ON (t.repository_id,t.digest_id,t.reference,t.platform,t.advisory_id)
            =(s.repository_id,s.digest_id,s.reference,s.platform,k.advisory_id)
        LEFT JOIN advisory_issue_links g ON g.advisory_id=a.id
        LEFT JOIN LATERAL active_finding_exception(s.repository_id,a.id,s.platform,s.reference) efx ON true
        WHERE ($1::text IS NULL OR p.name=$1) AND ($2::text IS NULL OR a.external_id=$2)
        AND ($8::text IS NULL OR a.external_id ILIKE '%'||$8||'%' OR k.title ILIKE '%'||$8||'%' OR p.name ILIKE '%'||$8||'%'
            OR coalesce(t.issue_key,g.issue_key) ILIKE '%'||$8||'%' OR s.reference ILIKE '%'||$8||'%')
        AND ($9::text IS NULL OR sev.name=lower($9)) AND ($10::text IS NULL OR coalesce(nullif(t.status,'open'),CASE WHEN efx.reason IS NOT NULL THEN 'excepted' ELSE 'open' END)=$10)
        AND (coalesce($11,false)=false OR coalesce(t.issue_url,g.issue_url) IS NOT NULL) AND ($12::text IS NULL OR e.name=ANY(string_to_array($12,',')))
        AND ($13::boolean IS NULL OR (k.fixed_in IS NOT NULL)=$13)
        AND (k.advisory_id,s.digest_id,k.package_id,s.repository_id,s.reference,s.platform)>($3,$4,$5,$6,$15::text,$16::text)
        ORDER BY k.advisory_id,s.digest_id,k.package_id,s.repository_id,s.reference,s.platform LIMIT $7"#)
        .bind(q.package).bind(q.advisory).bind(cursor.0).bind(cursor.1).bind(cursor.2).bind(cursor.3).bind(limit+1)
        .bind(q.q).bind(q.severity).bind(q.status).bind(q.linked).bind(q.ecosystems).bind(q.fixable)
        .bind(q.latest.unwrap_or(true)).bind(reference).bind(platform)
        .fetch_all(&app.0.database.reads).await?;
    let mut library = BTreeMap::new();
    let next = if rows.len() > limit as usize {
        let r = &rows[limit as usize - 1];
        Some(
            json!([
                r.aid,
                r.digest_id,
                r.pid,
                r.repository_id,
                [r.reference, r.platform]
            ])
            .to_string(),
        )
    } else {
        None
    };
    for r in rows.into_iter().take(limit as usize) {
        let group=library.entry(r.id.clone()).or_insert_with(||json!({"finding":{"id":r.id,"ecosystem":r.ecosystem,"package":r.package,"installed":r.installed,"fixed":r.fixed,"severity":r.severity,"title":r.title},"affected":[]}));
        group["affected"].as_array_mut().unwrap().push(json!({"reference":r.reference,"scanId":r.scan,
            "platform":r.platform,"digest":r.digest,"finishedAt":r.finished_at,"status":r.status,"package":r.package,"ecosystem":r.ecosystem,
            "installed":r.installed,"fixed":r.fixed,"severity":r.severity,"title":r.title,"purl":r.purl,"issue":r.issue,"exception":r.exception}));
    }
    let mut response = Json(library.into_values().collect::<Vec<_>>()).into_response();
    if let Some(next) = next {
        response
            .headers_mut()
            .insert("x-next-cursor", next.parse().map_err(ApiError::bad)?);
    }
    Ok(response)
}
#[derive(Deserialize)]
struct NamePage {
    cursor: Option<String>,
    limit: Option<i64>,
}
async fn packages(
    State(app): State<App>,
    Query(q): Query<NamePage>,
) -> ApiResult<(axum::http::HeaderMap, Json<Value>)> {
    let limit = crate::IdPage {
        cursor: None,
        limit: q.limit,
    }
    .limit()?;
    use base64::Engine;
    let cursor = q
        .cursor
        .map(|key| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(key)
                .map_err(ApiError::bad)
                .and_then(|bytes| String::from_utf8(bytes).map_err(ApiError::bad))
        })
        .transpose()?;
    let rows=sqlx::query!(r#"WITH names AS(SELECT DISTINCT p.name FROM package_counts c JOIN packages p ON p.id=c.package_id
        WHERE c.total>0 AND p.name>coalesce($1,'') ORDER BY p.name LIMIT $2)
        SELECT p.name,upper(s.name) AS "severity!",count(DISTINCT f.advisory_id) AS "total!" FROM names JOIN packages p USING(name)
        JOIN findings f ON f.package_id=p.id AND f.resolved_scan_id IS NULL JOIN advisories a ON a.id=f.advisory_id JOIN severities s ON s.id=a.severity_id
        GROUP BY p.name,s.name ORDER BY p.name"#,cursor,limit+1).fetch_all(&app.0.database.reads).await?;
    let mut packages = BTreeMap::<String, BTreeMap<String, i64>>::new();
    for row in rows {
        packages
            .entry(row.name)
            .or_default()
            .insert(row.severity, row.total);
    }
    let mut headers = axum::http::HeaderMap::new();
    if packages.len() > limit as usize {
        packages.pop_last();
        if let Some((key, _)) = packages.last_key_value() {
            use base64::Engine;
            headers.insert(
                "x-next-cursor",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(key)
                    .parse()
                    .map_err(ApiError::bad)?,
            );
        }
    }
    Ok((headers, Json(json!(packages))))
}
#[derive(Deserialize)]
struct EventPage {
    q: Option<String>,
    cursor: Option<i64>,
    limit: Option<i64>,
}
#[derive(sqlx::FromRow, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEvent {
    id: i64,
    action: String,
    resource: String,
    detail: String,
    created_at: chrono::DateTime<chrono::Utc>,
    actor_user_id: Option<Uuid>,
    actor_name: Option<String>,
    resource_label: Option<String>,
    resource_path: Option<String>,
}

async fn events(
    State(app): State<App>,
    Query(q): Query<EventPage>,
) -> ApiResult<crate::List<AuditEvent>> {
    let limit = crate::IdPage {
        cursor: None,
        limit: q.limit,
    }
    .limit()?;
    let rows = sqlx::query_as::<_, AuditEvent>(
        "WITH entries AS (
           SELECT a.*,nullif(u.display_name,'') AS actor_name,
             CASE WHEN a.resource ~* '^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$' THEN a.resource::uuid END AS target
           FROM audit_events a LEFT JOIN auth_users u ON u.id=a.actor_user_id
           WHERE ($1::bigint IS NULL OR a.id<$1)
             AND ($3::text IS NULL OR a.action ILIKE '%'||$3||'%' OR a.resource ILIKE '%'||$3||'%'
               OR a.detail ILIKE '%'||$3||'%' OR u.display_name ILIKE '%'||$3||'%')
           ORDER BY a.id DESC LIMIT $2
         ) SELECT a.id,a.action,a.resource,a.detail,a.created_at,a.actor_user_id,a.actor_name,
             coalesce(s.reference,t.name,r.name,k.name,p.reference) AS resource_label,
             CASE WHEN s.id IS NOT NULL THEN '/scans/'||s.id::text
                  WHEN t.id IS NOT NULL THEN '/scheduled-scans'
                  WHEN r.id IS NOT NULL THEN '/registries'
                  WHEN k.id IS NOT NULL THEN '/settings?section=issue-trackers'
                  WHEN p.id IS NOT NULL THEN '/patches' END AS resource_path
         FROM entries a
         LEFT JOIN scan_directory d ON a.action LIKE 'scan.%' AND d.id=a.target
         LEFT JOIN scans s ON s.id=d.id AND s.queued_at=d.queued_at
         LEFT JOIN schedules t ON a.action LIKE 'schedule.%' AND t.id=a.target
         LEFT JOIN registry_profiles r ON a.action LIKE 'registry.%' AND r.id=a.target
         LEFT JOIN issue_trackers k ON a.action LIKE 'issue_tracker.%' AND k.id=a.target
         LEFT JOIN patches p ON a.action LIKE 'patch.%' AND p.id=a.target
         ORDER BY a.id DESC",
    ).bind(q.cursor).bind(limit + 1).bind(q.q).fetch_all(&app.0.database.primary).await?;
    crate::page_rows(rows, limit, |event| event.id.to_string())
}
