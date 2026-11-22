use crate::{ApiError, ApiResult, App, ScanInput, image_target, scanner::Credentials};
use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{SecondsFormat, Utc};
use cron::Schedule;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{str::FromStr, time::Duration};
use uuid::Uuid;

pub fn routes() -> Router<App> {
    Router::new()
        .route("/scheduled-scans", get(schedules).post(create))
        .route("/scheduled-scans/history", get(history))
        .route(
            "/scheduled-scans/{id}",
            axum::routing::put(update).delete(remove),
        )
        .route("/scheduled-scans/{id}/execute", post(execute))
        .route("/settings", get(settings).put(save_settings))
        .route("/settings/notifications/test", post(test_notification))
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Selection {
    #[serde(default)]
    mode: Mode,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    image_pattern: String,
    #[serde(default)]
    tag_pattern: String,
    #[serde(default)]
    exclude_tag_pattern: String,
    #[serde(default)]
    retain_sbom: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kubernetes_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kubernetes_host: Option<String>,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    #[default]
    Specific,
    Pattern,
    All,
    Kubernetes,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScheduleInput {
    name: String,
    expression: String,
    enabled: bool,
    #[serde(flatten)]
    scan: ScanInput,
    #[serde(flatten)]
    selection: Selection,
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct Saved {
    id: String,
    name: String,
    reference: String,
    platform: String,
    registry_id: Option<String>,
    source: String,
    expression: String,
    enabled: bool,
    due_at: chrono::DateTime<Utc>,
    #[serde(flatten)]
    #[sqlx(json)]
    selection: Selection,
}

const SELECT: &str = "SELECT id::text AS id,name,reference,platform,registry_id::text AS registry_id,source,expression,enabled,due_at,selection FROM schedules";
fn next(expression: &str) -> Result<String> {
    anyhow::ensure!(
        expression.split_whitespace().count() == 5 && expression.len() <= 120,
        "Enter a five-field UTC cron expression."
    );
    let parsed = Schedule::from_str(&format!("0 {expression}"))
        .map_err(|_| anyhow::anyhow!("Enter a valid UTC cron expression."))?;
    Ok(parsed
        .upcoming(Utc)
        .next()
        .ok_or_else(|| anyhow::anyhow!("The schedule has no future runs."))?
        .to_rfc3339_opts(SecondsFormat::Secs, true))
}

async fn schedules(
    State(app): State<App>,
    axum::extract::Query(page): axum::extract::Query<crate::IdPage>,
) -> ApiResult<crate::List<Saved>> {
    let rows = sqlx::query_as::<_, Saved>(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE $1::uuid IS NULL OR schedules.id<$1 ORDER BY schedules.id DESC LIMIT $2"
    )))
    .bind(page.cursor)
    .bind(page.limit()? + 1)
    .fetch_all(&app.0.database.primary)
    .await?;
    crate::page_rows(rows, page.limit()?, |r| r.id.clone())
}
async fn write(app: &App, id: String, input: ScheduleInput, existing: bool) -> ApiResult<Saved> {
    let name = input.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::bad(
            "Enter a schedule name of up to 100 characters.",
        ));
    }
    let next_due = next(&input.expression).map_err(ApiError::bad)?;
    let mut selection = input.selection;
    selection.kubernetes_host = None;
    if !matches!(selection.mode, Mode::Kubernetes) {
        selection.kubernetes_namespace = None;
    }
    let (reference, platform, registry_id, source) = match selection.mode {
        Mode::Specific => {
            let mut refs = std::mem::take(&mut selection.references);
            if refs.is_empty() {
                refs.push(input.scan.reference.clone());
            }
            if refs.len() > 200 {
                return Err(ApiError::bad(
                    "Enter at most 200 specific image references.",
                ));
            }
            let mut targets = Vec::with_capacity(refs.len());
            for reference in refs {
                let target = image_target(
                    app,
                    ScanInput {
                        reference,
                        platform: input.scan.platform.clone(),
                        registry_id: input.scan.registry_id.clone(),
                        source: input.scan.source.clone(),
                        scanners: None,
                        priority: None,
                    },
                )
                .await?;
                if !selection.references.contains(&target.reference) {
                    selection.references.push(target.reference.clone());
                    targets.push(target);
                }
            }
            let first = targets.remove(0);
            (
                first.reference,
                first.platform,
                first.registry_id,
                first.source,
            )
        }
        Mode::Pattern | Mode::All => {
            filters(&selection).map_err(ApiError::bad)?;
            selection.references.clear();
            (String::new(), input.scan.platform, None, "registry".into())
        }
        Mode::Kubernetes => {
            crate::validate_platform(&input.scan.platform)?;
            selection.kubernetes_namespace = crate::discovery::validate_namespace(
                selection.kubernetes_namespace.as_deref().map(str::trim),
            )?
            .map(str::to_owned);
            selection.references.clear();
            if let Some(id) = &input.scan.registry_id {
                selection.kubernetes_host = Some(
                    crate::registries::credential_record(app, id)
                        .await?
                        .ok_or_else(|| ApiError::missing("Saved registry not found."))?
                        .0,
                );
            }
            (
                String::new(),
                input.scan.platform,
                input.scan.registry_id,
                "kubernetes".into(),
            )
        }
    };
    let sql = if existing {
        "UPDATE schedules SET name=$2,reference=$3,platform=$4,registry_id=$5,source=$6,expression=$7,enabled=$8,due_at=$9,selection=$10 WHERE id=$1"
    } else {
        "INSERT INTO schedules(id,name,reference,platform,registry_id,source,expression,enabled,due_at,selection) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
    };
    let due_at = next_due
        .parse::<chrono::DateTime<Utc>>()
        .map_err(ApiError::bad)?;
    let changed = sqlx::query(sql)
        .bind(crate::key(&id)?)
        .bind(name)
        .bind(&reference)
        .bind(&platform)
        .bind(registry_id.as_deref().map(crate::key).transpose()?)
        .bind(&source)
        .bind(&input.expression)
        .bind(input.enabled)
        .bind(due_at)
        .bind(sqlx::types::Json(&selection))
        .execute(&app.0.database.primary)
        .await?
        .rows_affected();
    if changed == 0 {
        return Err(ApiError::missing("Schedule not found."));
    }
    let item = Saved {
        id: id.clone(),
        name: name.to_owned(),
        reference,
        platform,
        registry_id,
        source,
        expression: input.expression,
        enabled: input.enabled,
        due_at,
        selection,
    };
    app.0
        .database
        .audit(
            if existing {
                "schedule.updated"
            } else {
                "schedule.created"
            },
            &id,
            name,
        )
        .await?;
    Ok(item)
}

async fn create(
    State(app): State<App>,
    Json(input): Json<ScheduleInput>,
) -> ApiResult<(StatusCode, Json<Saved>)> {
    Ok((
        StatusCode::CREATED,
        Json(write(&app, Uuid::now_v7().to_string(), input, false).await?),
    ))
}

async fn update(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<ScheduleInput>,
) -> ApiResult<Json<Saved>> {
    Ok(Json(write(&app, id, input, true).await?))
}

async fn remove(State(app): State<App>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    if sqlx::query!("DELETE FROM schedules WHERE id=$1", crate::key(&id)?)
        .execute(&app.0.database.primary)
        .await?
        .rows_affected()
        == 0
    {
        return Err(ApiError::missing("Schedule not found."));
    }
    app.0.database.audit("schedule.deleted", &id, "").await?;
    Ok(StatusCode::NO_CONTENT)
}

fn filter(pattern: &str) -> Result<Option<regex::Regex>> {
    if pattern.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(
        pattern.len() <= 250,
        "Each image or tag pattern must be 250 characters or fewer."
    );
    regex::RegexBuilder::new(pattern)
        .size_limit(512 * 1024)
        .build()
        .map(Some)
        .map_err(|_| anyhow::anyhow!("Enter a valid image or tag regular expression."))
}

struct Filters {
    image: Option<regex::Regex>,
    tag: Option<regex::Regex>,
    exclude: Option<regex::Regex>,
}

fn filters(selection: &Selection) -> Result<Filters> {
    let mut result = Filters {
        image: None,
        tag: None,
        exclude: None,
    };
    if matches!(selection.mode, Mode::Pattern) {
        result.image = filter(&selection.image_pattern)?;
        result.tag = filter(&selection.tag_pattern)?;
        result.exclude = filter(&selection.exclude_tag_pattern)?;
    }
    Ok(result)
}

type Target = (String, String, Option<String>, String);

fn matches_target(filters: &Filters, reference: &str) -> bool {
    let repo = crate::operations::repository(reference);
    let tag = reference[repo.len()..].trim_start_matches([':', '@']);
    filters.image.as_ref().is_none_or(|p| p.is_match(repo))
        && filters.tag.as_ref().is_none_or(|p| p.is_match(tag))
        && filters.exclude.as_ref().is_none_or(|p| !p.is_match(tag))
}

struct Run {
    id: Uuid,
    scans: Vec<Uuid>,
    total: usize,
}

async fn enqueue(app: &App, id: &str, manual: bool) -> ApiResult<Option<Run>> {
    let mut tx = app.0.database.primary.begin().await?;
    let key = crate::key(id)?;
    let Some(item) = sqlx::query_as::<_, Saved>(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE schedules.id=$1 FOR UPDATE"
    )))
    .bind(key)
    .fetch_optional(&mut *tx)
    .await?
    else {
        return Ok(None);
    };
    let run = Uuid::now_v7();
    if manual {
        sqlx::query!("INSERT INTO schedule_runs(id,schedule_id,name,nominal_time,trigger) VALUES($1,$2,$3,now(),'manual')",run,key,item.name).execute(&mut *tx).await?;
    } else {
        let next = next(&item.expression)?
            .parse::<chrono::DateTime<Utc>>()
            .map_err(anyhow::Error::from)?;
        if !sqlx::query_scalar!(
            r#"SELECT fire_schedule($1,$2,$3,$4) AS "fired!""#,
            key,
            item.due_at,
            next,
            run
        )
        .fetch_one(&mut *tx)
        .await?
        {
            return Ok(None);
        }
    }
    let specific = matches!(item.selection.mode, Mode::Specific);
    let kubernetes = if matches!(item.selection.mode, Mode::Kubernetes) {
        Some(kubernetes_targets(&mut tx, key, &item).await?)
    } else {
        None
    };
    let filters = filters(&item.selection)?;
    let mut cursor = (String::new(), String::new());
    let mut result = Run {
        id: run,
        scans: Vec::new(),
        total: 0,
    };
    loop {
        let chunk: Vec<Target> = if let Some(references) = &kubernetes {
            references
                .iter()
                .map(|reference| {
                    (
                        reference.clone(),
                        item.platform.clone(),
                        item.registry_id.clone(),
                        item.source.clone(),
                    )
                })
                .collect()
        } else if specific {
            let refs = if item.selection.references.is_empty() {
                std::slice::from_ref(&item.reference)
            } else {
                &item.selection.references
            };
            refs.iter()
                .map(|r| {
                    (
                        r.clone(),
                        item.platform.clone(),
                        item.registry_id.clone(),
                        item.source.clone(),
                    )
                })
                .collect()
        } else {
            sqlx::query_as("SELECT DISTINCT ON(reference,platform) reference,platform,registry_profile_id::text,source FROM scans
                WHERE source IN ('registry','docker','swarm','kubernetes') AND status='completed' AND (reference,platform)>($1,$2)
                ORDER BY reference,platform,queued_at DESC,id DESC LIMIT 200")
                .bind(&cursor.0).bind(&cursor.1).fetch_all(&mut *tx).await?
        };
        let done = kubernetes.is_some() || specific || chunk.len() < 200;
        if let Some(last) = chunk.last() {
            cursor = (last.0.clone(), last.1.clone());
        }
        let (mut ids, mut images, mut platforms, mut profiles, mut sources) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (reference, platform, profile, source) in chunk {
            if matches_target(&filters, &reference) {
                let id = Uuid::now_v7();
                ids.push(id);
                images.push(reference);
                platforms.push(platform);
                sources.push(source);
                profiles.push(profile.as_deref().map(crate::key).transpose()?);
                if result.scans.len() < 200 {
                    result.scans.push(id);
                }
            }
        }
        if !ids.is_empty() {
            sqlx::query!(
                "SELECT enqueue_schedule_jobs($1,$2,$3,$4,$5,$6)",
                run,
                &ids,
                &images,
                &platforms,
                &profiles as &[Option<Uuid>],
                &sources
            )
            .execute(&mut *tx)
            .await?;
            if item.selection.retain_sbom {
                sqlx::query("UPDATE scan_jobs SET retain_sbom=true WHERE scan_id=ANY($1)")
                    .bind(&ids)
                    .execute(&mut *tx)
                    .await?;
            }
            result.total += ids.len();
        }
        if done {
            break;
        }
    }
    tx.commit().await?;
    app.0
        .database
        .audit(
            "schedule.executed",
            id,
            &format!("{} scans queued", result.total),
        )
        .await?;
    Ok(Some(result))
}

async fn kubernetes_targets(
    tx: &mut sqlx::PgTransaction<'_>,
    schedule: Uuid,
    item: &Saved,
) -> ApiResult<std::collections::BTreeSet<String>> {
    let namespace = item.selection.kubernetes_namespace.as_deref();
    let host = item.selection.kubernetes_host.as_deref();
    if host.is_some() && item.registry_id.is_none() {
        return Err(ApiError::bad(
            "Choose a registry connection for this Kubernetes schedule.",
        ));
    }
    let scope = json!([namespace, item.platform, item.registry_id]);
    let previous = sqlx::query_scalar::<_, sqlx::types::Json<crate::discovery::RuntimeImages>>(
        "SELECT images FROM schedule_kubernetes_observations WHERE schedule_id=$1 AND scope=$2",
    )
    .bind(schedule)
    .bind(&scope)
    .fetch_optional(&mut **tx)
    .await?
    .map(|value| value.0)
    .unwrap_or_default();
    let (current, changed) =
        crate::discovery::kubernetes_observation(namespace, host, &previous).await?;
    sqlx::query(
        "INSERT INTO schedule_kubernetes_observations (schedule_id,scope,images) VALUES ($1,$2,$3)
        ON CONFLICT(schedule_id) DO UPDATE SET scope=excluded.scope,images=excluded.images",
    )
    .bind(schedule)
    .bind(scope)
    .bind(sqlx::types::Json(current))
    .execute(&mut **tx)
    .await?;
    Ok(changed)
}

async fn execute(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let scans = enqueue(&app, &id, true).await?.ok_or_else(|| {
        ApiError(
            StatusCode::CONFLICT,
            "The schedule is missing or the scan queue is full.".into(),
        )
    })?;
    Ok((
        StatusCode::ACCEPTED,
        Json(
            json!({ "id": scans.scans.first(), "scanIds": scans.scans, "total":scans.total,"runId":scans.id }),
        ),
    ))
}

#[derive(Deserialize)]
struct HistoryPage {
    cursor: Option<String>,
    limit: Option<i64>,
    run: Option<Uuid>,
}
async fn history(
    State(app): State<App>,
    axum::extract::Query(q): axum::extract::Query<HistoryPage>,
) -> ApiResult<crate::List<Value>> {
    let limit = crate::IdPage {
        cursor: None,
        limit: q.limit,
    }
    .limit()?;
    let before: Option<(Uuid, Uuid)> = q
        .cursor
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(ApiError::bad)?;
    let (run, scan) = before.unzip();
    let rows=sqlx::query_scalar!(r#"SELECT jsonb_build_object('id',h.id,'name',h.name,'scanId',r.scan_id,'createdAt',h.created_at,'trigger',h.trigger,
        'status',CASE WHEN r.scan_id IS NULL THEN 'no_matches' ELSE coalesce(s.status,'removed') END) AS "entry!"
        FROM schedule_runs h LEFT JOIN schedule_run_scans r ON r.run_id=h.id LEFT JOIN scan_directory d ON d.id=r.scan_id LEFT JOIN scans s ON s.id=d.id AND s.queued_at=d.queued_at
        WHERE ($1::uuid IS NULL OR (h.id,coalesce(r.scan_id,'00000000-0000-0000-0000-000000000000'))<($1,$2))
        AND ($3::uuid IS NULL OR h.id=$3) ORDER BY h.id DESC,r.scan_id DESC LIMIT $4"#,run,scan,q.run,limit+1).fetch_all(&app.0.database.primary).await?;
    crate::page_rows(rows, limit, |v| {
        json!([
            v["id"],
            v["scanId"]
                .as_str()
                .unwrap_or("00000000-0000-0000-0000-000000000000")
        ])
        .to_string()
    })
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    #[serde(default = "default_retention")]
    scan_days: u64,
    #[serde(default = "default_retention")]
    audit_days: u64,
    #[serde(default = "default_retention")]
    batch_days: u64,
    #[serde(default = "default_notification")]
    channel: String,
    #[serde(default)]
    notify_failures: bool,
    #[serde(default = "notify_scan_successes_by_default")]
    notify_scan_successes: bool,
    #[serde(default)]
    cleanup_s3_artifacts: bool,
}

fn default_retention() -> u64 {
    90
}
fn default_notification() -> String {
    "webhook".into()
}
fn notify_scan_successes_by_default() -> bool {
    true
}

async fn load(app: &App) -> Result<Settings> {
    let value = sqlx::query_scalar!("SELECT value FROM settings WHERE key='preferences'")
        .fetch_optional(&app.0.database.primary)
        .await?;
    Ok(serde_json::from_value(value.unwrap_or_else(|| json!({})))?)
}

async fn notification(app: &App) -> Result<Option<String>> {
    let secret = sqlx::query_scalar!("SELECT secret FROM notification_config WHERE singleton")
        .fetch_optional(&app.0.database.primary)
        .await?;
    Ok(secret
        .map(|value| app.0.vault.open_secret("notifications", &value))
        .transpose()?
        .map(|value| value.password))
}

async fn settings(State(app): State<App>) -> ApiResult<Json<Value>> {
    let mut response = serde_json::to_value(load(&app).await?).map_err(anyhow::Error::from)?;
    response["notificationConfigured"] = json!(notification(&app).await?.is_some());
    Ok(Json(response))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsInput {
    #[serde(flatten)]
    preferences: Settings,
    notification_url: Option<String>,
    #[serde(default)]
    remove_notification: bool,
}

async fn save_settings(
    State(app): State<App>,
    Json(input): Json<SettingsInput>,
) -> ApiResult<StatusCode> {
    let values = input.preferences;
    if ![values.scan_days, values.audit_days, values.batch_days]
        .into_iter()
        .all(|days| (1..=365).contains(&days))
        || !["webhook", "slack", "teams", "gotify", "apprise"].contains(&values.channel.as_str())
    {
        return Err(ApiError::bad(
            "Enter retention periods between 1 and 365 days and select a notification channel.",
        ));
    }
    let credential =
        if let Some(endpoint) = input.notification_url.filter(|url| !url.trim().is_empty()) {
            let parsed = url::Url::parse(endpoint.trim())
                .map_err(|_| ApiError::bad("Enter a valid HTTPS webhook URL."))?;
            if parsed.scheme() != "https"
                || parsed.host().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
            {
                return Err(ApiError::bad("Enter a valid HTTPS webhook URL."));
            }
            Some(app.0.vault.seal(
                "notifications",
                &Credentials {
                    username: String::new(),
                    password: parsed.to_string(),
                },
            )?)
        } else {
            None
        };
    let mut tx = app.0.database.primary.begin().await?;
    let preferences = serde_json::to_value(&values).map_err(anyhow::Error::from)?;
    sqlx::query!(
        "INSERT INTO settings(key,value) VALUES('preferences',$1)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        preferences
    )
    .execute(&mut *tx)
    .await?;
    if input.remove_notification {
        sqlx::query!("DELETE FROM notification_config WHERE singleton")
            .execute(&mut *tx)
            .await?;
    } else if let Some(secret) = credential {
        sqlx::query!(
            "INSERT INTO notification_config(singleton,secret) VALUES(true,$1)
                     ON CONFLICT(singleton) DO UPDATE SET secret=excluded.secret",
            secret
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    app.0
        .database
        .audit("settings.updated", "instance", "")
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn notify(endpoint: String, channel: &str, text: &str) -> Result<()> {
    let body = match channel {
        "slack" => json!({"text":text}),
        "teams" => {
            json!({"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive",
            "content":{"type":"AdaptiveCard","version":"1.2","body":[{"type":"TextBlock","text":text,"wrap":true}]}}]})
        }
        "gotify" => json!({"title":crate::PRODUCT_NAME,"message":text,"priority":5}),
        "apprise" => json!({"title":crate::PRODUCT_NAME,"body":text,"type":"info"}),
        _ => json!({"application":crate::PRODUCT_NAME,"message":text}),
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8))
        .build()?;
    let response = client
        .post(endpoint)
        .json(&body)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Could not contact the webhook."))?;
    anyhow::ensure!(
        response.status().is_success(),
        "The webhook returned HTTP {}.",
        response.status()
    );
    Ok(())
}

async fn test_notification(State(app): State<App>) -> ApiResult<StatusCode> {
    let endpoint = notification(&app)
        .await?
        .ok_or_else(|| ApiError::bad("Save a notification URL first."))?;
    notify(
        endpoint,
        &load(&app).await?.channel,
        &format!("{} notification test", crate::PRODUCT_NAME),
    )
    .await
    .map_err(ApiError::bad)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn publish_result(app: &App, id: &str, reference: &str, succeeded: bool) {
    let Ok(settings) = load(app).await else {
        return;
    };
    if (succeeded && !settings.notify_scan_successes) || (!succeeded && !settings.notify_failures) {
        return;
    }
    if let Ok(Some(endpoint)) = notification(app).await {
        let message = format!(
            "Scan {} for {reference}",
            if succeeded { "completed" } else { "failed" }
        );
        let result = notify(endpoint, &settings.channel, &message).await;
        if let Err(error) = result {
            let _ = app
                .0
                .database
                .audit("notification.failed", id, &error.to_string())
                .await;
        }
    }
}

pub async fn send_alert(app: &App, text: &str) -> Result<bool> {
    let Some(endpoint) = notification(app).await? else {
        return Ok(false);
    };
    notify(endpoint, &load(app).await?.channel, text).await?;
    Ok(true)
}

async fn due(app: &App) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar!(r#"SELECT id::text AS "id!" FROM schedules WHERE enabled AND due_at<=now() ORDER BY due_at,id LIMIT 50"#).fetch_all(&app.0.database.primary).await?)
}
async fn cleanup(app: &App) -> Result<()> {
    let settings = load(app).await?;
    sqlx::query!(
        "SELECT retain_storage($1,$2)",
        i32::try_from(settings.scan_days)?,
        i32::try_from(settings.audit_days)?
    )
    .execute(&app.0.database.primary)
    .await?;
    let mut tx = app.0.database.primary.begin().await?;
    sqlx::query(
        "DELETE FROM scan_observed_findings o USING scan_directory d
        WHERE o.scan_no=d.scan_no AND d.queued_at < now()-make_interval(days=>$1)
        AND NOT EXISTS (SELECT FROM scans s WHERE (s.id,s.queued_at)=(d.id,d.queued_at))",
    )
    .bind(i32::try_from(settings.scan_days)?)
    .execute(&mut *tx)
    .await?;
    let batches = i32::try_from(settings.batch_days)?;
    sqlx::query!(
        "DELETE FROM batches WHERE created_at<now()-$1::integer * interval '1 day'",
        batches
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!("DELETE FROM schedule_run_scans r USING schedule_runs s WHERE r.run_id=s.id AND s.created_at<now()-$1::integer * interval '1 day'",batches).execute(&mut *tx).await?;
    sqlx::query!(
        "DELETE FROM schedule_runs WHERE created_at<now()-$1::integer * interval '1 day'",
        batches
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!("DELETE FROM watch_alerts WHERE next_attempt IS NULL AND created_at<now()-$1::integer * interval '1 day'",i32::try_from(settings.audit_days)?).execute(&mut *tx).await?;
    tx.commit().await?;
    crate::artifact_blob::collect(app, settings.cleanup_s3_artifacts).await
}

pub async fn clock(app: App) {
    let mut ticks = tokio::time::interval(Duration::from_secs(15));
    let mut sweep = tokio::time::interval(Duration::from_secs(3600));
    let mut delivery: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        tokio::select! {
            _ = ticks.tick() => {
                if let Ok(items) = due(&app).await {
                    for id in items { if let Err(error) = enqueue(&app, &id, false).await { eprintln!("Scheduler: {error:#}"); } }
                }
                if delivery.as_ref().is_none_or(|task| task.is_finished()) {
                    let app = app.clone();
                    delivery = Some(tokio::spawn(async move {
                        if let Err(error) = crate::watches::deliver_pending(&app).await {
                            eprintln!("Watch notification: {error:#}");
                        }
                    }));
                }
            }
            _ = sweep.tick() => {
                if let Err(error) = cleanup(&app).await { eprintln!("Retention: {error:#}"); }

            },
        }
    }
}
