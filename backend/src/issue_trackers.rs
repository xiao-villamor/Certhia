use crate::{ApiError, ApiResult, App};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, put},
};

use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

pub const PROVIDERS: &[&str] = &[
    "jira",
    "linear",
    "github",
    "gitlab",
    "youtrack",
    "plane",
    "openproject",
    "redmine",
    "other",
];
const PLACEHOLDER: &str = "{id}";

pub fn routes() -> Router<App> {
    Router::new()
        .route("/settings/issue-trackers", get(list).post(create))
        .route("/settings/issue-trackers/{id}", put(update).delete(remove))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrackerInput {
    name: String,
    provider: String,
    url_template: String,
}

#[derive(Serialize)]
struct Tracker {
    id: String,
    #[serde(flatten)]
    config: TrackerInput,
}

fn issue_url(input: &str) -> Option<Url> {
    let (scheme, _) = input.split_once("://")?;
    if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        || input.len() > 2048
        || input.chars().any(char::is_control)
    {
        return None;
    }
    let parsed = Url::parse(input).ok()?;
    (parsed.host().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.as_str().len() <= 2048)
        .then_some(parsed)
}

impl TrackerInput {
    fn validate(mut self) -> ApiResult<Self> {
        self.name = self.name.trim().to_owned();
        self.url_template = self.url_template.trim().to_owned();
        if self.name.is_empty() || self.name.len() > 100 || self.name.chars().any(char::is_control)
        {
            return Err(ApiError::bad("Enter a tracker name of up to 100 bytes."));
        }
        if !PROVIDERS.contains(&self.provider.as_str()) {
            return Err(ApiError::bad("Choose an issue tracker provider."));
        }
        let problem = || {
            ApiError::bad(
                "Enter an HTTP or HTTPS issue URL template with one {id} in its path, query, or fragment.",
            )
        };
        let (prefix, suffix) = self
            .url_template
            .split_once(PLACEHOLDER)
            .ok_or_else(problem)?;
        const SAMPLE: &str = "HGISSUEKEYPLACEHOLDER";
        if suffix.contains(PLACEHOLDER)
            || self.url_template.contains(SAMPLE)
            || self.url_template.len() > 1900
        {
            return Err(problem());
        }
        let sample = issue_url(&format!("{prefix}{SAMPLE}{suffix}")).ok_or_else(problem)?;
        if ![Some(sample.path()), sample.query(), sample.fragment()]
            .into_iter()
            .flatten()
            .any(|part| part.contains(SAMPLE))
        {
            return Err(problem());
        }
        Ok(self)
    }
}

async fn list(
    State(app): State<App>,
    axum::extract::Query(q): axum::extract::Query<crate::IdPage>,
) -> ApiResult<crate::List<Tracker>> {
    let rows = sqlx::query!(
        "SELECT id,name,provider,url_template FROM issue_trackers WHERE $1::uuid IS NULL OR id<$1 ORDER BY id DESC LIMIT $2",q.cursor,q.limit()?+1
    )
    .fetch_all(&app.0.database.primary)
    .await?;
    let trackers = rows
        .into_iter()
        .map(|r| Tracker {
            id: r.id.to_string(),
            config: TrackerInput {
                name: r.name,
                provider: r.provider,
                url_template: r.url_template,
            },
        })
        .collect();
    crate::page_rows(trackers, q.limit()?, |r| r.id.clone())
}

async fn create(
    State(app): State<App>,
    Json(input): Json<TrackerInput>,
) -> ApiResult<(StatusCode, Json<Tracker>)> {
    let config = input.validate()?;
    let id = Uuid::now_v7().to_string();
    sqlx::query!(
        "INSERT INTO issue_trackers VALUES($1,$2,$3,$4)",
        crate::key(&id)?,
        config.name,
        config.provider,
        config.url_template
    )
    .execute(&app.0.database.primary)
    .await?;
    app.0
        .database
        .audit("issue_tracker.added", &id, &config.name)
        .await?;
    Ok((StatusCode::CREATED, Json(Tracker { id, config })))
}

async fn update(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<TrackerInput>,
) -> ApiResult<Json<Tracker>> {
    let config = input.validate()?;
    let changed = sqlx::query!(
        "UPDATE issue_trackers SET name=$2,provider=$3,url_template=$4 WHERE id=$1",
        crate::key(&id)?,
        config.name,
        config.provider,
        config.url_template
    )
    .execute(&app.0.database.primary)
    .await?
    .rows_affected();
    if changed == 0 {
        return Err(ApiError::missing("Issue tracker not found."));
    }
    app.0
        .database
        .audit("issue_tracker.updated", &id, &config.name)
        .await?;
    Ok(Json(Tracker { id, config }))
}

async fn remove(State(app): State<App>, Path(id): Path<String>) -> ApiResult<StatusCode> {
    let changed = sqlx::query!("DELETE FROM issue_trackers WHERE id=$1", crate::key(&id)?)
        .execute(&app.0.database.primary)
        .await?
        .rows_affected();
    if changed == 0 {
        return Err(ApiError::missing("Issue tracker not found."));
    }
    app.0
        .database
        .audit("issue_tracker.removed", &id, "")
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueSelection {
    tracker_id: String,
    key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueLink {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracker_id: Option<String>,
    pub tracker: String,
    pub url: String,
    pub key: String,
}

pub async fn resolve(db: &mut sqlx::PgConnection, input: IssueSelection) -> ApiResult<IssueLink> {
    let key = input.key.trim();
    let key = key.strip_prefix('#').unwrap_or(key);
    if key.is_empty()
        || key.len() > 100
        || !key.as_bytes()[0].is_ascii_alphanumeric()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ApiError::bad("Enter an issue ID such as SEC-123 or 42."));
    }
    let row = sqlx::query!(
        "SELECT provider,url_template FROM issue_trackers WHERE id=$1 FOR SHARE",
        crate::key(&input.tracker_id)?
    )
    .fetch_optional(db)
    .await?
    .ok_or_else(|| ApiError::missing("Choose a saved issue tracker."))?;
    let (tracker, template) = (row.provider, row.url_template);
    let url = issue_url(&template.replace(PLACEHOLDER, key)).ok_or_else(|| {
        ApiError::bad("The saved tracker could not build an issue URL for this ID.")
    })?;
    Ok(IssueLink {
        tracker_id: Some(input.tracker_id),
        tracker,
        url: url.into(),
        key: key.into(),
    })
}
