use crate::{ApiError, ApiResult, App, IdPage, artifacts, store::ScanDetail};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use uuid::Uuid;

pub fn routes() -> Router<App> {
    Router::new()
        .route("/scans/{id}/report/summary", get(summary))
        .route("/scans/{id}/report/findings", get(findings))
        .route(
            "/scans/{id}/report/scanner-differences",
            get(scanner_differences),
        )
}

const SCAN: &str = "SELECT s.repository_id,s.digest_id,s.reference,s.platform,d.observed_order,d.scan_no,s.observation_complete
    FROM scan_directory d JOIN scans s USING(id,queued_at) WHERE d.id=$1
    AND s.status='completed'";

#[derive(Serialize, Deserialize, sqlx::FromRow)]
struct Facet {
    ecosystem: String,
    severity: String,
    count: i64,
}

#[derive(Serialize)]
struct Summary {
    #[serde(flatten)]
    detail: ScanDetail,
    facets: Vec<Facet>,
}

async fn summary(State(app): State<App>, Path(id): Path<Uuid>) -> ApiResult<Json<Summary>> {
    let detail = app
        .0
        .database
        .scan_summary(&id.to_string())
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    let facets = if detail.report.is_some() {
        sqlx::query_as::<_, Facet>(sqlx::AssertSqlSafe(format!(
            "WITH scan AS ({SCAN})
             SELECT e.name AS ecosystem,sev.name AS severity,count(*) AS count FROM scan s
             CROSS JOIN LATERAL observed_findings(s.digest_id,s.observed_order,s.scan_no,s.observation_complete IS NOT NULL) k
             JOIN packages p ON p.id=k.package_id JOIN ecosystems e ON e.id=p.ecosystem_id
             JOIN severities sev ON sev.id=k.severity_id GROUP BY e.name,sev.name"
        ))).bind(id).fetch_all(&app.0.database.primary).await?
    } else {
        Vec::new()
    };
    Ok(Json(Summary { detail, facets }))
}

async fn index_evidence(app: &App, id: Uuid) -> ApiResult<bool> {
    if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT FROM report_evidence_index WHERE scan_id=$1)",
    )
    .bind(id)
    .fetch_one(&app.0.database.primary)
    .await?
    {
        return Ok(true);
    }
    let scan = id.to_string();
    let job = app
        .0
        .database
        .replay(&scan)
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    let detections = match artifacts::detections(app, &scan, &job.source).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(scan_id=%id, %error, "Could not index finding evidence");
            return Ok(false);
        }
    };
    let mut tx = app.0.database.primary.begin().await?;
    if sqlx::query("INSERT INTO report_evidence_index(scan_id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0
        && !detections.is_empty()
    {
        sqlx::query(
            "WITH detected AS (
               SELECT d.id,d.aliases,d.scanner,p.id AS package_id FROM
               jsonb_to_recordset($2) d(id text,aliases text[],ecosystem text,package text,installed text,purl text,scanner text)
               JOIN ecosystems e ON e.name=d.ecosystem JOIN packages p ON p.ecosystem_id=e.id
               AND p.name=d.package AND p.version=d.installed AND p.purl IS NOT DISTINCT FROM d.purl
             ), candidate AS (
               SELECT d.*,a.advisory FROM detected d
               CROSS JOIN LATERAL (SELECT DISTINCT unnest(array_prepend(d.id,d.aliases)) AS advisory) a
             ), owners AS (
               SELECT package_id,advisory,count(DISTINCT id) FILTER(WHERE id<>advisory) AS other
               FROM candidate GROUP BY package_id,advisory
             )
             INSERT INTO report_finding_evidence(scan_id,package_id,advisory,aliases,scanners)
             SELECT $1,c.package_id,c.advisory,
               coalesce(array_agg(DISTINCT a.id ORDER BY a.id) FILTER(WHERE a.id<>c.advisory),'{}'),
               array_agg(DISTINCT c.scanner ORDER BY c.scanner)
             FROM candidate c JOIN owners o USING(package_id,advisory)
             CROSS JOIN LATERAL unnest(array_prepend(c.id,c.aliases)) a(id)
             WHERE o.other<=1 OR c.id=c.advisory GROUP BY c.package_id,c.advisory"
        ).bind(id).bind(json!(detections)).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(true)
}

#[derive(Deserialize)]
struct FindingQuery {
    cursor: Option<String>,
    limit: Option<i64>,
    q: Option<String>,
    advisory: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    // Ordered groups of raw package types from the summary.
    groups: Option<String>,
    collapsed: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingPage {
    items: Vec<Value>,
    next_cursor: Option<String>,
    facets: Option<Vec<Facet>>,
    evidence_available: bool,
}

type FindingCursor = (i64, i32, String, i32, i32);

fn cursor<T: DeserializeOwned>(value: &str) -> ApiResult<T> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad("Invalid page cursor."))?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::bad("Invalid page cursor."))
}

fn decode_groups<T: DeserializeOwned>(value: Option<&str>) -> ApiResult<Option<T>> {
    value
        .map(|value| {
            serde_json::from_str(value).map_err(|_| ApiError::bad("Invalid ecosystem selection."))
        })
        .transpose()
}

async fn findings(
    State(app): State<App>,
    Path(id): Path<Uuid>,
    Query(q): Query<FindingQuery>,
) -> ApiResult<Json<FindingPage>> {
    let limit = IdPage {
        cursor: None,
        limit: q.limit,
    }
    .limit()?;
    let position = q
        .cursor
        .as_deref()
        .map(cursor::<FindingCursor>)
        .transpose()?;
    let groups: Option<Vec<Vec<String>>> = decode_groups(q.groups.as_deref())?;
    let collapsed: Vec<String> = decode_groups(q.collapsed.as_deref())?.unwrap_or_default();
    let evidence_available = index_evidence(&app, id).await?;
    let cte = format!(
        "WITH scan AS ({SCAN}), order_by_ecosystem AS (
            SELECT name,min(g.position) AS position FROM jsonb_array_elements($5::jsonb) WITH ORDINALITY g(kinds,position)
            CROSS JOIN LATERAL jsonb_array_elements_text(g.kinds) e(name) GROUP BY name
         ), matches AS (
            SELECT coalesce(o.position,0) AS group_no,-k.severity_id::integer AS rank,
                a.external_id AS advisory,a.id AS advisory_id,p.id AS package_id,p.name AS package,p.purl,p.version AS installed,
                e.name AS ecosystem,sev.name AS severity,coalesce(k.title,'') AS title,coalesce(f.version,'') AS fixed,
                coalesce(ev.aliases,'{{}}') AS aliases,coalesce(ev.scanners,'{{}}') AS scanners,
                jsonb_build_object('finding',a.external_id,'status',coalesce(t.status,'open'),'note',coalesce(t.note,''),
                  'updatedAt',t.updated_at,
                  'issue',CASE WHEN t.tracker IS NOT NULL THEN jsonb_strip_nulls(jsonb_build_object('tracker',t.tracker,
                    'trackerId',t.tracker_id,'url',t.issue_url,'key',t.issue_key))
                    WHEN g.tracker IS NOT NULL THEN jsonb_strip_nulls(jsonb_build_object('tracker',g.tracker,
                    'trackerId',g.tracker_id,'url',g.issue_url,'key',g.issue_key,'scope','advisory')) END,
                  'exception',CASE WHEN ex.reference IS NOT NULL THEN jsonb_build_object('scope',CASE WHEN ex.reference=''
                    THEN 'repository' ELSE 'reference' END,'reason',ex.reason,'expiresAt',ex.expires_at) END) AS tracking
            FROM scan s
            CROSS JOIN LATERAL observed_findings(s.digest_id,s.observed_order,s.scan_no,s.observation_complete IS NOT NULL) k
            JOIN packages p ON p.id=k.package_id JOIN ecosystems e ON e.id=p.ecosystem_id
            JOIN advisories a ON a.id=k.advisory_id JOIN severities sev ON sev.id=k.severity_id
            LEFT JOIN order_by_ecosystem o ON o.name=e.name
            LEFT JOIN fix_versions f ON f.id=k.fixed_in
            LEFT JOIN report_finding_evidence ev ON (ev.scan_id,ev.package_id,ev.advisory)=($1,p.id,a.external_id)
            LEFT JOIN image_finding_tracking t ON (t.repository_id,t.digest_id,t.reference,t.platform,t.advisory_id)
                =(s.repository_id,s.digest_id,s.reference,s.platform,a.id)
            LEFT JOIN advisory_issue_links g ON g.advisory_id=a.id
            LEFT JOIN LATERAL active_finding_exception(s.repository_id,a.id,s.platform,s.reference) ex ON true
            WHERE ($2::text IS NULL OR a.external_id=$2)
              AND ($3::text IS NULL OR sev.name=$3)
              AND ($4::text IS NULL OR (CASE WHEN coalesce(t.status,'open')='open' AND ex.reference IS NOT NULL
                THEN 'excepted' ELSE coalesce(t.status,'open') END)=$4)
              AND ($5::jsonb IS NULL OR o.position IS NOT NULL)
              AND ($6::text IS NULL OR strpos(lower(concat_ws(E'\\n',a.external_id,p.name,e.name,sev.name,k.title,
                array_to_string(ev.aliases,' '),coalesce(t.issue_key,g.issue_key))),lower($6))>0)
         )"
    );
    let groups = groups.map(sqlx::types::Json);
    let search =
        q.q.as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
    let bind = |statement: String| {
        sqlx::query_scalar::<_, Value>(sqlx::AssertSqlSafe(statement))
            .bind(id)
            .bind(&q.advisory)
            .bind(&q.severity)
            .bind(&q.status)
            .bind(&groups)
            .bind(search)
    };
    let (group, rank, advisory, package, advisory_id) = position.clone().unwrap_or_default();
    let select = format!(
        "{cte} SELECT jsonb_build_object('id',advisory,'ecosystem',ecosystem,'package',package,'installed',installed,
           'purl',purl,'fixed',fixed,'severity',upper(severity),'title',title,'aliases',aliases,'detectedBy',scanners,'tracking',tracking,
           '_cursor',jsonb_build_array(group_no,rank,advisory,package_id,advisory_id))
         FROM matches WHERE NOT ecosystem=ANY($7)
           AND ($8::bigint IS NULL OR (group_no,rank,advisory,package_id,advisory_id)>($8,$9,$10,$11,$12))
         ORDER BY group_no,rank,advisory,package_id,advisory_id LIMIT $13"
    );
    let mut items = bind(select)
        .bind(&collapsed)
        .bind(position.as_ref().map(|_| group))
        .bind(rank)
        .bind(advisory)
        .bind(package)
        .bind(advisory_id)
        .bind(limit + 1)
        .fetch_all(&app.0.database.primary)
        .await?;
    let next_cursor = if items.len() > limit as usize {
        items.truncate(limit as usize);
        Some(URL_SAFE_NO_PAD.encode(items.last().unwrap()["_cursor"].to_string()))
    } else {
        None
    };
    for item in &mut items {
        item.as_object_mut().unwrap().remove("_cursor");
    }
    let facets = if position.is_none() {
        let count = format!("{cte} SELECT coalesce(jsonb_agg(to_jsonb(rows)),'[]') FROM
            (SELECT ecosystem,severity,count(*) AS count FROM matches GROUP BY ecosystem,severity) rows");
        let raw = bind(count).fetch_one(&app.0.database.primary).await?;
        Some(serde_json::from_value(raw).map_err(anyhow::Error::from)?)
    } else {
        None
    };
    Ok(Json(FindingPage {
        items,
        next_cursor,
        facets,
        evidence_available,
    }))
}

async fn index_discrepancies(app: &App, id: Uuid) -> ApiResult<Value> {
    if let Some(summary) =
        sqlx::query_scalar("SELECT summary FROM report_discrepancy_index WHERE scan_id=$1")
            .bind(id)
            .fetch_optional(&app.0.database.primary)
            .await?
    {
        return Ok(summary);
    }
    let bytes = artifacts::discrepancies(app, &id.to_string())
        .await
        .map_err(ApiError::bad)?
        .ok_or_else(|| {
            ApiError::bad(
                "A comparison requires completed reports from at least two vulnerability scanners.",
            )
        })?;
    let mut data: Value = serde_json::from_slice(&bytes).map_err(anyhow::Error::from)?;
    let entries = data
        .as_object_mut()
        .and_then(|value| value.remove("differences"))
        .unwrap_or_else(|| json!([]));
    let mut tx = app.0.database.primary.begin().await?;
    if sqlx::query("INSERT INTO report_discrepancy_index(scan_id,summary) VALUES ($1,$2) ON CONFLICT DO NOTHING")
        .bind(id).bind(&data).execute(&mut *tx).await?.rows_affected()>0
    {
        sqlx::query(
            "INSERT INTO report_discrepancy_entries(scan_id,reconciled,ordinal,entry,search_text)
             SELECT $1,entry->>'status'='auto_resolved',ordinal,entry,
               lower(concat_ws(' ',entry->>'reasons',jsonb_path_query_array(entry,'$.*.advisory')::text,
                 jsonb_path_query_array(entry,'$.*.id')::text,jsonb_path_query_array(entry,'$.*.package')::text,
                 jsonb_path_query_array(entry,'$.*.version')::text,jsonb_path_query_array(entry,'$.*.aliases[*]')::text))
             FROM jsonb_array_elements($2) WITH ORDINALITY rows(entry,ordinal)"
        ).bind(id).bind(entries).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(data)
}

#[derive(Deserialize)]
struct DifferenceQuery {
    cursor: Option<String>,
    limit: Option<i64>,
    status: Option<String>,
    q: Option<String>,
}

async fn scanner_differences(
    State(app): State<App>,
    Path(id): Path<Uuid>,
    Query(q): Query<DifferenceQuery>,
) -> ApiResult<Json<Value>> {
    let limit = IdPage {
        cursor: None,
        limit: q.limit,
    }
    .limit()?;
    let position = q.cursor.as_deref().map(cursor::<(bool, i64)>).transpose()?;
    let reconciled = match q.status.as_deref() {
        Some("auto_resolved") => Some(true),
        Some("needs_review") => Some(false),
        None => None,
        _ => return Err(ApiError::bad("Invalid scanner difference status.")),
    };
    let summary = if position.is_none() {
        Some(index_discrepancies(&app, id).await?)
    } else {
        None
    };
    let mut rows = sqlx::query_as::<_, (bool, i64, Value)>(
        "SELECT reconciled,ordinal,entry FROM report_discrepancy_entries
         WHERE scan_id=$1 AND ($2::boolean IS NULL OR reconciled=$2)
         AND ($3::text IS NULL OR strpos(search_text,lower($3))>0)
         AND ($4::boolean IS NULL OR (reconciled,ordinal)>($4,$5))
         ORDER BY reconciled,ordinal LIMIT $6",
    )
    .bind(id)
    .bind(reconciled)
    .bind(q.q.as_deref().map(str::trim))
    .bind(position.map(|p| p.0))
    .bind(position.map(|p| p.1))
    .bind(limit + 1)
    .fetch_all(&app.0.database.primary)
    .await?;
    let next = if rows.len() > limit as usize {
        rows.truncate(limit as usize);
        let (kind, id, _) = rows.last().unwrap();
        Some(URL_SAFE_NO_PAD.encode(json!([kind, id]).to_string()))
    } else {
        None
    };
    Ok(Json(
        json!({"summary":summary,"items":rows.into_iter().map(|row|row.2).collect::<Vec<_>>(),"nextCursor":next}),
    ))
}
