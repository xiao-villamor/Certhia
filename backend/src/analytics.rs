use crate::{ApiError, ApiResult, App};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

pub fn routes() -> Router<App> {
    Router::new()
        .route("/dashboard", get(dashboard))
        .route("/library/top-packages", get(top_packages))
        .route("/library/advisories", get(advisories))
        .route("/library/advisories/{id}/digests", get(impact))
        .route("/advisories/{id}", get(advisory_details))
        .route("/repositories/{id}/findings", get(repository_findings))
        .route("/digests/{a}/compare/{b}", get(compare))
}
#[derive(Deserialize)]
struct Page {
    cursor: Option<String>,
    limit: Option<i64>,
    q: Option<String>,
}
impl Page {
    fn cursor<T: DeserializeOwned + Default>(&self) -> ApiResult<T> {
        self.cursor
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map(|v| v.unwrap_or_default())
            .map_err(ApiError::bad)
    }
    fn limit(&self) -> ApiResult<i64> {
        crate::IdPage {
            cursor: None,
            limit: self.limit,
        }
        .limit()
    }
    fn result(&self, mut rows: Vec<(Value, Value)>) -> ApiResult<Json<Value>> {
        let limit = self.limit()? as usize;
        let next = if rows.len() > limit {
            rows.truncate(limit);
            rows.last().map(|(_, key)| key.to_string())
        } else {
            None
        };
        Ok(Json(
            json!({"items":rows.into_iter().map(|(item,_)|item).collect::<Vec<_>>(),"nextCursor":next}),
        ))
    }
}
async fn dashboard(State(app): State<App>) -> ApiResult<Json<Value>> {
    let rows=sqlx::query!(r#"SELECT s.name,coalesce(sum(c.total),0)::bigint AS "total!" FROM severities s LEFT JOIN dashboard_counts c ON c.severity_id=s.id GROUP BY s.name"#).fetch_all(&app.0.database.reads).await?;
    let counts = rows
        .into_iter()
        .map(|r| (r.name, json!(r.total)))
        .collect::<serde_json::Map<_, _>>();
    let row=sqlx::query!(r#"SELECT coalesce(sum(total),0)::bigint AS "scans!",coalesce(sum(total) FILTER(WHERE status='completed'),0)::bigint AS "completed!",
        coalesce(sum(total) FILTER(WHERE status IN ('queued','running')),0)::bigint AS "active!",
        coalesce(sum(total) FILTER(WHERE status='failed'),0)::bigint AS "failed!",
        (SELECT count(*) FROM registry_profiles) AS "registries!" FROM scan_status_counts WHERE to_regclass('scans_'||to_char(month,'YYYYMM')) IS NOT NULL"#).fetch_one(&app.0.database.reads).await?;
    Ok(Json(
        json!({"severity":counts,"scans":row.scans,"completed":row.completed,"registries":row.registries,"active":row.active,"failed":row.failed}),
    ))
}
async fn top_packages(State(app): State<App>, Query(q): Query<Page>) -> ApiResult<Json<Value>> {
    let before: Option<(i64, i32)> = q.cursor()?;
    let (total, id) = before.unzip();
    let rows=sqlx::query!("SELECT p.name,p.version,c.package_id,c.total FROM package_counts c JOIN packages p ON p.id=c.package_id
        WHERE c.total>0 AND ($1::bigint IS NULL OR c.total<$1 OR (c.total=$1 AND c.package_id>$2)) AND ($3::text IS NULL OR p.name ILIKE '%'||$3||'%')
        ORDER BY c.total DESC,c.package_id LIMIT $4",total,id,q.q,q.limit()?+1).fetch_all(&app.0.database.reads).await?;
    q.result(
        rows.into_iter()
            .map(|r| {
                (
                    json!({"id":r.package_id,"name":r.name,"version":r.version,"total":r.total}),
                    json!([r.total, r.package_id]),
                )
            })
            .collect(),
    )
}
async fn advisories(State(app): State<App>, Query(q): Query<Page>) -> ApiResult<Json<Value>> {
    let (name, id): (String, i32) = q.cursor()?;
    let rows=sqlx::query!(r#"SELECT a.id,a.external_id,a.summary,s.name AS severity,coalesce(c.affected_images,0) AS "affected!"
        FROM advisories a JOIN severities s ON s.id=a.severity_id LEFT JOIN advisory_counts c ON c.advisory_id=a.id
        WHERE (external_id,a.id)>($1,$2) AND ($3::text IS NULL OR external_id ILIKE '%'||$3||'%')
        ORDER BY external_id,a.id LIMIT $4"#,name,id,q.q,q.limit()?+1).fetch_all(&app.0.database.reads).await?;
    q.result(rows.into_iter().map(|r|(json!({"id":r.id,"externalId":r.external_id,"severity":r.severity,"summary":r.summary,"affectedImages":r.affected}),json!([r.external_id,r.id]))).collect())
}
/// Advisory metadata recorded from scanner reports. A row exists per scanner source, so the
/// most recently modified record with a description wins.
async fn advisory_details(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let detail: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id',a.external_id,'source',a.source,'severity',s.name,'summary',a.summary,
            'description',a.description,'cvssScore',a.cvss_score,'cvssVector',a.cvss_vector,'epss',a.epss,'kev',a.kev,
            'references',coalesce(a.refs,'[]'::jsonb),'publishedAt',a.published_at,'modifiedAt',a.modified_at)
         FROM advisories a JOIN severities s ON s.id=a.severity_id WHERE a.external_id=$1
         ORDER BY (a.description IS NULL),a.modified_at DESC NULLS LAST,a.id LIMIT 1",
    )
    .bind(&id)
    .fetch_optional(&app.0.database.reads)
    .await?;
    detail
        .map(Json)
        .ok_or_else(|| ApiError::missing("Advisory not found."))
}
async fn impact(
    State(app): State<App>,
    Path(id): Path<i32>,
    Query(q): Query<Page>,
) -> ApiResult<Json<Value>> {
    let before: i64 = q.cursor()?;
    let rows=sqlx::query!("SELECT d.id,d.digest FROM (SELECT DISTINCT digest_id FROM findings WHERE advisory_id=$1 AND resolved_scan_id IS NULL AND digest_id>$2
        ORDER BY digest_id LIMIT $3) p JOIN digests d ON d.id=p.digest_id ORDER BY d.id",id,before,q.limit()?+1).fetch_all(&app.0.database.reads).await?;
    q.result(
        rows.into_iter()
            .map(|r| (json!({"id":r.id,"digest":r.digest}), json!(r.id)))
            .collect(),
    )
}
async fn repository_findings(
    State(app): State<App>,
    Path(id): Path<i64>,
    Query(q): Query<Page>,
) -> ApiResult<Json<Value>> {
    let (d, p, a): (i64, i32, i32) = q.cursor()?;
    let rows=sqlx::query!("SELECT rd.digest_id,f.package_id,f.advisory_id,f.fixed_in FROM repository_digests rd CROSS JOIN LATERAL (
        SELECT package_id,advisory_id,fixed_in FROM findings WHERE digest_id=rd.digest_id AND resolved_scan_id IS NULL
        AND (digest_id,package_id,advisory_id)>($2,$3,$4) ORDER BY package_id,advisory_id LIMIT $5)f
        WHERE rd.repository_id=$1 AND rd.digest_id>=$2 ORDER BY rd.digest_id,f.package_id,f.advisory_id LIMIT $5",id,d,p,a,q.limit()?+1).fetch_all(&app.0.database.reads).await?;
    q.result(rows.into_iter().map(|r|(json!({"digestId":r.digest_id,"packageId":r.package_id,"advisoryId":r.advisory_id,"fixVersionId":r.fixed_in}),json!([r.digest_id,r.package_id,r.advisory_id]))).collect())
}
async fn compare(
    State(app): State<App>,
    Path((a, b)): Path<(i64, i64)>,
    Query(q): Query<Page>,
) -> ApiResult<Json<Value>> {
    let (p, v): (i32, i32) = q.cursor()?;
    let rows=sqlx::query!(r#"WITH baseline AS(SELECT package_id,advisory_id FROM findings WHERE digest_id=$1 AND resolved_scan_id IS NULL),
        target AS(SELECT package_id,advisory_id FROM findings WHERE digest_id=$2 AND resolved_scan_id IS NULL)
        SELECT package_id AS "package!",advisory_id AS "advisory!",(baseline.package_id IS NULL) AS "added!" FROM baseline FULL JOIN target USING(package_id,advisory_id)
        WHERE (baseline.package_id IS NULL OR target.package_id IS NULL) AND (package_id,advisory_id)>($3,$4)
        ORDER BY package_id,advisory_id LIMIT $5"#,a,b,p,v,q.limit()?+1).fetch_all(&app.0.database.reads).await?;
    q.result(
        rows.into_iter()
            .map(|r| {
                (
                    json!({"packageId":r.package,"advisoryId":r.advisory,"added":r.added}),
                    json!([r.package, r.advisory]),
                )
            })
            .collect(),
    )
}
