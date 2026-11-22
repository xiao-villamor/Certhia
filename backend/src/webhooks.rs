use crate::{
    ApiError, ApiResult, App, ImageReference, ImageTarget, PLATFORMS, jobs, validate_platform,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use subtle::ConstantTimeEq;
use uuid::Uuid;

pub fn routes() -> Router<App> {
    Router::new()
        .route(
            "/registries/{id}/webhook",
            get(configuration).post(generate).delete(revoke),
        )
        .route("/webhooks/registries/{id}/ci", post(ci))
        .route("/webhooks/registries/{id}/ci/{scan_id}", get(ci_result))
        .route("/webhooks/registries/{id}/harbor", post(harbor))
        .layer(DefaultBodyLimit::max(128 * 1024))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Configuration {
    ci_path: String,
    harbor_path: String,
    created_at: Option<String>,
}

fn configuration_for(id: &str, created_at: Option<String>) -> Configuration {
    let base = format!("/api/webhooks/registries/{id}");
    Configuration {
        ci_path: format!("{base}/ci"),
        harbor_path: format!("{base}/harbor"),
        created_at,
    }
}

async fn configuration(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Json<Configuration>> {
    let key = Uuid::parse_str(&id).map_err(|_| ApiError::missing("Saved registry not found."))?;
    let created_at=sqlx::query_scalar!(r#"SELECT w.created_at AS "created_at?" FROM registry_profiles p LEFT JOIN registry_webhooks w
        ON p.id=w.registry_id WHERE p.id=$1"#,key).fetch_optional(&app.0.database.primary).await?
        .ok_or_else(||ApiError::missing("Saved registry not found."))?.map(|t|t.to_rfc3339());
    Ok(Json(configuration_for(&id, created_at)))
}

async fn generate(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<([(header::HeaderName, &'static str); 1], Json<Value>)> {
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .map_err(|_| anyhow::anyhow!("System random source unavailable"))?;
    let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(seed));
    let hash = Sha256::digest(token.as_bytes());
    let key = Uuid::parse_str(&id).map_err(|_| ApiError::missing("Saved registry not found."))?;
    let created_at = chrono::Utc::now();
    let changed = sqlx::query!(
        "INSERT INTO registry_webhooks(registry_id,token_hash,created_at)
        SELECT id,$2,$3 FROM registry_profiles WHERE id=$1 ON CONFLICT(registry_id)
        DO UPDATE SET token_hash=excluded.token_hash,created_at=excluded.created_at",
        key,
        hash.as_slice(),
        created_at
    )
    .execute(&app.0.database.primary)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::missing("Saved registry not found."));
    }
    app.0
        .database
        .audit("registry.webhook.generated", &id, "")
        .await?;
    let mut response = serde_json::to_value(configuration_for(&id, Some(created_at.to_rfc3339())))
        .map_err(anyhow::Error::from)?;
    response["token"] = json!(token);
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(response)))
}

async fn revoke(State(app): State<App>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let Ok(key) = Uuid::parse_str(&id) else {
        return Ok(StatusCode::NO_CONTENT);
    };
    let changed = sqlx::query!("DELETE FROM registry_webhooks WHERE registry_id=$1", key)
        .execute(&app.0.database.primary)
        .await?
        .rows_affected();
    if changed > 0 {
        app.0
            .database
            .audit("registry.webhook.revoked", &id, "")
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn authorize(app: &App, id: &str, headers: &HeaderMap) -> ApiResult<String> {
    let unauthorized = || {
        ApiError(
            StatusCode::UNAUTHORIZED,
            "A valid registry webhook token is required.".into(),
        )
    };
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.strip_prefix("Bearer ").unwrap_or(value))
        .filter(|value| valid_token_format(value))
        .ok_or_else(unauthorized)?;
    let id = Uuid::parse_str(id).map_err(|_| unauthorized())?;
    let saved=sqlx::query!("SELECT r.host,w.token_hash FROM registry_webhooks w
        JOIN registry_profiles p ON p.id=w.registry_id JOIN registries r ON r.id=p.registry_id WHERE w.registry_id=$1",id)
        .fetch_optional(&app.0.database.primary).await?.ok_or_else(unauthorized)?;
    let (host, hash) = (saved.host, saved.token_hash);
    if !bool::from(
        hash.as_slice()
            .ct_eq(Sha256::digest(token.as_bytes()).as_slice()),
    ) {
        return Err(unauthorized());
    }
    Ok(host)
}

const TOKEN_PREFIX: &str = "certhia_wh_";

// Tokens are checked against their stored hash. Any short lowercase prefix is
// accepted here so tokens issued before the current prefix stay valid.
fn valid_token_format(token: &str) -> bool {
    token.split_once("_wh_").is_some_and(|(prefix, secret)| {
        (1..=16).contains(&prefix.len())
            && prefix.bytes().all(|byte| byte.is_ascii_lowercase())
            && secret.len() == 43
    })
}

#[derive(Deserialize)]
struct CiInput {
    reference: String,
    platform: Option<String>,
}

async fn ci(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<CiInput>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let platform = input.platform.as_deref().unwrap_or(PLATFORMS[0]);
    queue(&app, &id, &headers, platform, "ci", |host| {
        let reference =
            ImageReference::parse(&input.reference, Some(host)).map_err(ApiError::bad)?;
        Ok(BTreeSet::from([reference.value]))
    })
    .await
}

async fn ci_result(
    State(app): State<App>,
    Path((registry_id, scan_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<([(header::HeaderName, &'static str); 1], Json<Value>)> {
    authorize(&app, &registry_id, &headers).await?;
    let result = sqlx::query_scalar::<_, Value>(
        "SELECT jsonb_build_object('id',s.id,'reference',s.reference,'platform',s.platform,
            'status',s.status,'reportUrl','/scans/'||s.id::text,
            'observationComplete',s.observation_complete,'scanners',coalesce(string_to_array(s.scanner,', '),'{}'),
            'fixableHigh',f.high,'fixableCritical',f.critical)
         FROM ci_scan_results g JOIN scan_directory d ON d.id=g.scan_id JOIN scans s USING(id,queued_at)
         LEFT JOIN LATERAL (
            SELECT count(*) FILTER (WHERE severity=3) AS high,
                   count(*) FILTER (WHERE severity=4) AS critical
            FROM (
                SELECT max(k.severity_id) AS severity
                FROM observed_findings(s.digest_id,d.observed_order,d.scan_no,true) k
                WHERE s.status='completed' AND s.observation_complete=true AND k.fixed_in IS NOT NULL
                GROUP BY k.advisory_id
            ) fixable
         ) f ON s.status='completed' AND s.observation_complete=true
         WHERE g.registry_id=$1 AND g.scan_id=$2 AND g.expires_at>now()",
    ).bind(crate::key(&registry_id)?).bind(crate::key(&scan_id)?)
        .fetch_optional(&app.0.database.primary).await?
        .ok_or_else(|| ApiError::missing("CI scan result not found."))?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(result)))
}

#[derive(Deserialize)]
struct HarborEvent {
    #[serde(rename = "type")]
    kind: String,
    event_data: Option<Value>,
    data: Option<Value>,
}

#[derive(Deserialize)]
struct HarborData {
    resources: Vec<HarborResource>,
}

#[derive(Deserialize)]
struct HarborResource {
    resource_url: String,
    digest: Option<String>,
}

fn harbor_references(event: HarborEvent, host: &str) -> ApiResult<BTreeSet<String>> {
    let payload = match event.kind.as_str() {
        "PUSH_ARTIFACT" => event.event_data,
        "harbor.artifact.pushed" => event.data,
        _ => return Ok(BTreeSet::new()),
    }
    .ok_or_else(|| ApiError::bad("The Harbor push event is missing its payload."))?;
    let data: HarborData = serde_json::from_value(payload)
        .map_err(|_| ApiError::bad("The Harbor push event must include its artifact resources."))?;
    if !(1..=50).contains(&data.resources.len()) {
        return Err(ApiError::bad(
            "The Harbor push event must contain 1 to 50 resources.",
        ));
    }
    data.resources
        .into_iter()
        .map(|resource| {
            let value = resource.resource_url.trim();
            let value = value
                .strip_prefix("https://")
                .or_else(|| value.strip_prefix("http://"))
                .unwrap_or(value);
            let (authority, _) = value.split_once('/').ok_or_else(|| {
                ApiError::bad("The Harbor resource must include a registry host.")
            })?;
            if crate::registry_host(authority).map_err(ApiError::bad)? != host {
                return Err(ApiError::bad(
                    "The Harbor resource must match the saved registry host.",
                ));
            }
            let reference = ImageReference::parse(value, Some(host))
                .map_err(ApiError::bad)?
                .value;
            let Some(digest) = resource.digest.filter(|digest| !digest.is_empty()) else {
                return Ok(reference);
            };
            let (repository, _) = reference
                .split_once('@')
                .or_else(|| reference.rsplit_once(':'))
                .expect("canonical OCI image references contain a tag or digest");
            Ok(
                ImageReference::parse(&format!("{repository}@{digest}"), Some(host))
                    .map_err(ApiError::bad)?
                    .value,
            )
        })
        .collect()
}

async fn harbor(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(event): Json<HarborEvent>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    queue(&app, &id, &headers, PLATFORMS[0], "harbor", |host| {
        harbor_references(event, host)
    })
    .await
}

async fn queue(
    app: &App,
    registry_id: &str,
    headers: &HeaderMap,
    platform: &str,
    trigger: &str,
    references: impl FnOnce(&str) -> ApiResult<BTreeSet<String>>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let host = authorize(app, registry_id, headers).await?;
    let registry_key = crate::key(registry_id)?;
    let mut tx = app.0.database.primary.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(192387115)")
        .execute(&mut *tx)
        .await?;
    validate_platform(platform)?;
    let references = references(&host)?;
    if references.is_empty() {
        return Ok((StatusCode::OK, Json(json!({"ignored":true,"scanIds":[]}))));
    }
    let mut ids = Vec::with_capacity(references.len());
    let mut queued = 0;
    for reference in references {
        let active=sqlx::query_scalar!("SELECT id FROM scans WHERE registry_profile_id=$1 AND reference=$2 AND platform=$3
            AND source='registry' AND status IN ('queued','running') ORDER BY queued_at DESC LIMIT 1",registry_key,reference,platform)
            .fetch_optional(&mut *tx).await?.map(|id|id.to_string());
        if let Some(id) = active {
            ids.push(id);
            continue;
        }
        let id = Uuid::now_v7().to_string();
        let target = ImageTarget {
            reference,
            platform: platform.into(),
            registry_id: Some(registry_id.into()),
            source: "registry".into(),
            scanners: Vec::new(),
            priority: 0,
        };
        if !jobs::insert_queued(&mut tx, &id, &target).await? {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "The scan queue has insufficient space. Retry this webhook later.".into(),
            ));
        }
        sqlx::query!(
            "INSERT INTO audit_events(action,resource,detail) VALUES('scan.webhook.queued',$1,$2)",
            id,
            format!("{trigger}: {}", target.reference)
        )
        .execute(&mut *tx)
        .await?;
        ids.push(id);
        queued += 1;
    }
    if trigger == "ci" {
        for id in &ids {
            sqlx::query(
                "INSERT INTO ci_scan_results (registry_id,scan_id,expires_at)
                VALUES ($1,$2,now()+interval '24 hours')
                ON CONFLICT(registry_id,scan_id) DO UPDATE SET expires_at=excluded.expires_at",
            )
            .bind(registry_key)
            .bind(crate::key(id)?)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;
    if queued > 0 {
        app.0.work.notify_waiters();
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"scanIds":ids,"queued":queued})),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_tokens_support_current_and_earlier_prefixes() {
        let payload = URL_SAFE_NO_PAD.encode([42; 32]);
        assert!(valid_token_format(&format!("{TOKEN_PREFIX}{payload}")));
        assert!(valid_token_format(&format!("ab_wh_{payload}")));
        assert!(!valid_token_format(&format!("AB_wh_{payload}")));
        assert!(!valid_token_format(&payload));
        assert!(!valid_token_format(&format!("{TOKEN_PREFIX}{payload}=")));
    }
}
