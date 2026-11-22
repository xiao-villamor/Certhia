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
    let rows=sqlx::query_scalar!(r#"SELECT jsonb_build_object('finding',a.external_id,'status',t.status,'note',t.note,'updatedAt',t.updated_at,
        'issue',CASE WHEN t.tracker IS NOT NULL THEN jsonb_strip_nulls(jsonb_build_object('tracker',t.tracker,'trackerId',t.tracker_id,'url',t.issue_url,'key',t.issue_key)) END) AS "entry!"
        FROM scan_directory d JOIN scans s USING(id,queued_at)
        JOIN image_finding_tracking t USING(repository_id,digest_id,reference,platform)
        JOIN advisories a ON a.id=t.advisory_id
        WHERE d.id=$1 AND a.external_id>coalesce($2,'') AND ($4::text IS NULL OR a.external_id=$4)
        ORDER BY a.external_id LIMIT $3"#,crate::key(&id)?,q.cursor,limit+1,q.finding).fetch_all(&app.0.database.primary).await?;
    crate::page_rows(rows, limit, |r| r["finding"].as_str().unwrap().to_string())
}

#[derive(Deserialize)]
struct ClassificationPage {
    cursor: Option<String>,
    limit: Option<i64>,
    finding: Option<String>,
}

#[derive(Deserialize)]
struct ClassificationInput {
    finding: String,
    status: String,
    #[serde(default)]
    note: String,
    #[serde(default, deserialize_with = "deserialize_issue_update")]
    issue: Option<Option<IssueSelection>>,
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
    let row=sqlx::query!(r#"SELECT s.reference,s.platform,s.repository_id AS "repository!",s.digest_id AS "digest!",a.id AS advisory
        FROM scan_directory d JOIN scans s USING(id,queued_at)
        JOIN LATERAL scan_finding_keys(s.digest_id,d.observed_order) k ON true JOIN advisories a ON a.id=k.advisory_id
        WHERE d.id=$1 AND a.external_id=$2 LIMIT 1"#,scan_id,input.finding).fetch_optional(&mut *tx).await?.ok_or_else(||ApiError::missing("Finding not present in this report."))?;
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
    sqlx::query!("INSERT INTO image_finding_tracking AS existing
        (repository_id,digest_id,reference,platform,advisory_id,status,note,updated_at,tracker_id,tracker,issue_url,issue_key)
        VALUES($1,$2,$3,$4,$5,$6,$7,now(),$8,$9,$10,$11)
        ON CONFLICT(repository_id,digest_id,reference,platform,advisory_id) DO UPDATE SET
            status=excluded.status,note=excluded.note,updated_at=excluded.updated_at,
            tracker_id=CASE WHEN $12 THEN excluded.tracker_id ELSE existing.tracker_id END,
            tracker=CASE WHEN $12 THEN excluded.tracker ELSE existing.tracker END,
            issue_url=CASE WHEN $12 THEN excluded.issue_url ELSE existing.issue_url END,
            issue_key=CASE WHEN $12 THEN excluded.issue_key ELSE existing.issue_key END",
        row.repository,row.digest,row.reference,row.platform,row.advisory,input.status,input.note,
        tracker_id,issue.as_ref().map(|link| link.tracker.as_str()),issue.as_ref().map(|link| link.url.as_str()),
        issue.as_ref().map(|link| link.key.as_str()),replace_issue).execute(&mut *tx).await?;
    sqlx::query!("INSERT INTO vex_reviews VALUES($1,$2,$3,$4,now()) ON CONFLICT(scan_id,advisory_id) DO UPDATE SET status=excluded.status,note=excluded.note,reviewed_at=now()",scan_id,row.advisory,input.status,input.note).execute(&mut *tx).await?;
    tx.commit().await?;
    app.0
        .database
        .audit("finding.classified", &row.reference, &input.finding)
        .await?;
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
    let rows=sqlx::query!(r#"SELECT a.id AS aid,f.digest_id,p.id AS pid,rd.repository_id,a.external_id AS id,e.name AS ecosystem,p.name AS package,p.version AS installed,p.purl,
        coalesce(v.version,'') AS "fixed!",upper(sev.name) AS "severity!",coalesce(a.summary,'') AS "title!",
        s.reference,s.platform,s.finished_at,s.id AS scan,d.digest,coalesce(t.status,'open') AS "status!",
        CASE WHEN t.tracker IS NOT NULL THEN jsonb_strip_nulls(jsonb_build_object('tracker',t.tracker,'trackerId',t.tracker_id,'url',t.issue_url,'key',t.issue_key)) END AS issue
        FROM findings f JOIN advisories a ON a.id=f.advisory_id JOIN packages p ON p.id=f.package_id JOIN ecosystems e ON e.id=p.ecosystem_id
        JOIN severities sev ON sev.id=a.severity_id LEFT JOIN fix_versions v ON v.id=f.fixed_in
        JOIN repository_digests rd USING(digest_id) JOIN digests d ON d.id=f.digest_id
        JOIN LATERAL (
          SELECT DISTINCT ON (s.reference,s.platform) s.reference,s.platform,s.finished_at,s.id,sd.observed_order
          FROM scans s JOIN scan_directory sd USING(id,queued_at)
          WHERE s.repository_id=rd.repository_id AND s.digest_id=f.digest_id AND s.status='completed'
          AND ($14::boolean IS DISTINCT FROM true OR position('@' in s.reference)>0 OR s.reference LIKE 'sha256:%' OR EXISTS (
            SELECT FROM image_tags tag WHERE tag.repository_id=rd.repository_id AND tag.platform=s.platform
              AND tag.tag=substring(s.reference from '[^:]+$') AND tag.digest_id=f.digest_id))
          ORDER BY s.reference,s.platform,s.finished_at DESC NULLS LAST,s.id DESC
        )s ON true
        LEFT JOIN image_finding_tracking t ON (t.repository_id,t.digest_id,t.reference,t.platform,t.advisory_id)
            =(rd.repository_id,f.digest_id,s.reference,s.platform,f.advisory_id)
        WHERE f.resolved_scan_id IS NULL AND ($1::text IS NULL OR p.name=$1) AND ($2::text IS NULL OR a.external_id=$2)
        AND EXISTS (SELECT FROM scan_finding_keys(f.digest_id,s.observed_order) k
            WHERE k.advisory_id=f.advisory_id AND k.package_id=f.package_id)
        AND ($8::text IS NULL OR a.external_id ILIKE '%'||$8||'%' OR a.summary ILIKE '%'||$8||'%' OR p.name ILIKE '%'||$8||'%'
            OR t.issue_key ILIKE '%'||$8||'%' OR s.reference ILIKE '%'||$8||'%')
        AND ($9::text IS NULL OR sev.name=lower($9)) AND ($10::text IS NULL OR coalesce(t.status,'open')=$10)
        AND (coalesce($11,false)=false OR t.issue_url IS NOT NULL) AND ($12::text IS NULL OR e.name=ANY(string_to_array($12,',')))
        AND ($13::boolean IS NULL OR (f.fixed_in IS NOT NULL)=$13)
        AND (f.advisory_id,f.digest_id,f.package_id,rd.repository_id)>=($3,$4,$5,$6)
        AND (f.advisory_id,f.digest_id,f.package_id,rd.repository_id,s.reference,s.platform)>($3,$4,$5,$6,$15::text,$16::text)
        ORDER BY f.advisory_id,f.digest_id,f.package_id,rd.repository_id,s.reference,s.platform LIMIT $7"#,
        q.package,q.advisory,cursor.0,cursor.1,cursor.2,cursor.3,limit+1,q.q,q.severity,q.status,q.linked,q.ecosystems,q.fixable,q.latest,reference,platform)
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
            "installed":r.installed,"fixed":r.fixed,"purl":r.purl,"issue":r.issue}));
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
        "SELECT id,action,resource,detail,created_at,actor_user_id FROM audit_events
         WHERE ($1::bigint IS NULL OR id<$1)
         AND ($3::text IS NULL OR action ILIKE '%'||$3||'%' OR resource ILIKE '%'||$3||'%' OR detail ILIKE '%'||$3||'%')
         ORDER BY id DESC LIMIT $2",
    ).bind(q.cursor).bind(limit + 1).bind(q.q).fetch_all(&app.0.database.primary).await?;
    crate::page_rows(rows, limit, |event| event.id.to_string())
}
