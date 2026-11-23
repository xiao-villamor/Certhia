use super::{Session, access, accounts, audit, oidc};
use crate::{ApiError, ApiResult, App};
use axum::{Extension, Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, types::Json as DbJson};
use url::Url;
use uuid::Uuid;

pub const ID: &str = "workspace-sso";

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub allowed_domains: Vec<String>,
    pub enabled: bool,
    pub jit: bool,
    pub trust_email: bool,
    pub secret_post: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    settings: Settings,
    client_secret: Option<String>,
}

#[derive(sqlx::FromRow)]
pub struct Stored {
    pub revision: Uuid,
    pub settings: DbJson<Settings>,
    pub client_secret: Vec<u8>,
}

impl Settings {
    fn validate(&mut self) -> ApiResult<()> {
        self.name = accounts::name(&self.name)?.to_owned();
        self.issuer = self.issuer.trim().to_owned();
        self.client_id = self.client_id.trim().to_owned();
        if self.issuer.len() > 2048 || self.issuer.chars().any(char::is_control) {
            return Err(ApiError::bad("Enter a valid OIDC issuer URL."));
        }
        oidc::parse_issuer(&self.issuer).map_err(ApiError::bad)?;
        if self.client_id.is_empty()
            || self.client_id.len() > 512
            || self.client_id.chars().any(char::is_control)
        {
            return Err(ApiError::bad("Enter a valid client ID."));
        }
        if self.allowed_domains.is_empty() || self.allowed_domains.len() > 32 {
            return Err(ApiError::bad(
                "Enter between 1 and 32 allowed email domains.",
            ));
        }
        for domain in &mut self.allowed_domains {
            *domain = oidc::normalize_domain(domain.trim()).map_err(ApiError::bad)?;
        }
        self.allowed_domains.sort_unstable();
        self.allowed_domains.dedup();
        Ok(())
    }

    fn secret_purpose(&self) -> String {
        format!(
            "auth/oidc/{ID}/{}",
            serde_json::json!([self.issuer, self.client_id])
        )
    }
}

impl Stored {
    pub fn into_provider(self, app: &App) -> ApiResult<oidc::Provider> {
        let secret = app
            .0
            .vault
            .open_bytes(&self.settings.secret_purpose(), &self.client_secret)?;
        let secret = String::from_utf8(secret).map_err(anyhow::Error::from)?;
        Ok(oidc::Provider::workspace(
            self.settings.0,
            secret,
            self.revision,
        ))
    }
}

pub fn origin(app: &App, headers: &HeaderMap) -> Option<Url> {
    let authority = access::host(headers)?;
    if let Some(origin) = &app.0.auth.origin {
        let request = Url::parse(&format!("{}://{authority}/", origin.scheme())).ok()?;
        return (request.origin() == origin.origin()).then(|| origin.clone());
    }
    if !app.0.auth.secure && !app.0.auth.mixed && access::loopback(authority.host()) {
        return Url::parse(&format!("http://{authority}/")).ok();
    }
    None
}

pub fn callback_url(origin: &Url, id: &str) -> Url {
    let mut redirect = origin.clone();
    redirect.set_path(&format!("/api/auth/oidc/{id}/callback"));
    redirect
}

fn conflict(app: &App, settings: Option<&Settings>) -> bool {
    app.0
        .auth
        .providers
        .iter()
        .any(|p| p.id == ID || settings.is_some_and(|settings| p.issuer() == settings.issuer))
}

async fn stored<'a>(
    db: impl sqlx::Executor<'a, Database = sqlx::Postgres>,
) -> ApiResult<Option<Stored>> {
    Ok(sqlx::query_as(
        "SELECT settings,revision,client_secret FROM auth_workspace_oidc WHERE singleton",
    )
    .fetch_optional(db)
    .await?)
}

pub async fn active(app: &App) -> ApiResult<Option<Stored>> {
    Ok(stored(&app.0.database.primary)
        .await?
        .filter(|row| row.settings.enabled && !conflict(app, Some(&row.settings))))
}

pub async fn revision_active(db: &mut PgConnection, revision: Uuid) -> ApiResult<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM auth_workspace_oidc WHERE singleton AND revision=$1)",
    )
    .bind(revision)
    .fetch_one(db)
    .await?)
}

pub async fn email_linking(app: &App) -> ApiResult<bool> {
    Ok(app
        .0
        .auth
        .providers
        .iter()
        .any(|provider| provider.link_by_email)
        || active(app).await?.is_some())
}

pub async fn get(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let row = stored(&app.0.database.primary).await?;
    Ok(Json(view(
        &app,
        row.as_ref().map(|row| &row.settings.0),
        origin(&app, &headers).as_ref(),
    )))
}

fn view(app: &App, settings: Option<&Settings>, origin: Option<&Url>) -> Value {
    json!({
        "settings": settings,
        "callbackUrl": origin.map(|origin| callback_url(origin, ID)),
        "deploymentConflict": conflict(app, settings),
        "deploymentProviders": app.0.auth.providers.iter().map(|provider| &provider.name).collect::<Vec<_>>(),
    })
}

pub async fn save(
    State(app): State<App>,
    Extension(session): Extension<Session>,
    headers: HeaderMap,
    Json(mut input): Json<Input>,
) -> ApiResult<Json<Value>> {
    let redirect_origin = origin(&app, &headers)
        .filter(|origin| {
            headers
                .get("origin")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == origin.origin().ascii_serialization())
        })
        .ok_or_else(|| {
            ApiError::bad("Open Certhia at its configured sign-in origin to manage single sign-on.")
        })?;
    input.settings.validate()?;
    if input.settings.enabled && conflict(&app, Some(&input.settings)) {
        return Err(ApiError::bad(
            "A deployment-managed provider already uses this issuer or callback.",
        ));
    }
    let mut tx = accounts::admin_transaction(&app.0.database.primary, &session).await?;
    let prior = stored(&mut *tx).await?;
    let secret = match input.client_secret.filter(|secret| !secret.is_empty()) {
        Some(secret) if secret.len() <= 4096 && !secret.chars().any(char::is_control) => app
            .0
            .vault
            .seal_bytes(&input.settings.secret_purpose(), secret.as_bytes())?,
        Some(_) => return Err(ApiError::bad("Enter a valid client secret.")),
        None => prior
            .filter(|row| {
                row.settings.issuer == input.settings.issuer
                    && row.settings.client_id == input.settings.client_id
            })
            .map(|row| row.client_secret)
            .ok_or_else(|| {
                ApiError::bad("Enter the client secret for this issuer and client ID.")
            })?,
    };
    sqlx::query(
        "INSERT INTO auth_workspace_oidc (revision, settings, client_secret) VALUES ($1, $2, $3)
         ON CONFLICT (singleton) DO UPDATE SET revision=excluded.revision, settings=excluded.settings, client_secret=excluded.client_secret",
    )
    .bind(Uuid::now_v7()).bind(DbJson(&input.settings)).bind(secret).execute(&mut *tx).await?;
    audit(
        &mut tx,
        "auth.sso.updated",
        None,
        Some(session.user.id),
        if input.settings.enabled {
            "Single sign-on enabled"
        } else {
            "Single sign-on disabled"
        },
    )
    .await?;
    tx.commit().await?;
    Ok(Json(view(
        &app,
        Some(&input.settings),
        Some(&redirect_origin),
    )))
}
