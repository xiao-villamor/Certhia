mod access;
mod accounts;
mod oidc;
mod workspace_sso;

use crate::{ApiError, ApiResult, App};
use anyhow::{Context, Result, bail, ensure};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    routing::{get, post, put},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{net::IpAddr, time::Duration};
use url::Url;
use uuid::Uuid;

pub use access::Session;
pub use access::{Access, authorize, classify, host as request_host};
pub use accounts::initialize;

#[derive(
    Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, sqlx::Type,
)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "text", rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Operator,
    Admin,
}

#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct User {
    id: Uuid,
    email: String,
    display_name: String,
    role: Role,
    disabled: bool,
    has_password: bool,
}

tokio::task_local! {
    static ACTOR: Uuid;
}

pub fn actor() -> Option<Uuid> {
    ACTOR.try_with(|id| *id).ok()
}

pub struct Config {
    local: bool,
    secure: bool,
    /// Plain HTTP and HTTPS origins both reach the dashboard (`auto` cookie mode).
    mixed: bool,
    origin: Option<Url>,
    trusted_proxies: Vec<IpAddr>,
    setup_hash: Option<[u8; 32]>,
    providers: Vec<oidc::Provider>,
    oidc_http: oidc::HttpClient,
    dummy_hash: String,
    password_slots: std::sync::Arc<tokio::sync::Semaphore>,
}

pub struct Startup {
    pub config: Config,
}

impl Config {
    pub fn load(allowed_hosts: &[String]) -> Result<Startup> {
        let local = flag("CERTHIA_AUTH_LOCAL", true)?;
        // `auto` serves both HTTPS and plain HTTP (for example a LAN address next to
        // a TLS proxy). Cookies then omit Secure, so use it only on trusted networks.
        let (secure, mixed) = match optional_env("CERTHIA_AUTH_SECURE_COOKIE").as_deref() {
            None | Some("1") => (true, false),
            Some("0") => (false, false),
            Some("auto") => (false, true),
            Some(_) => bail!("CERTHIA_AUTH_SECURE_COOKIE must be 0, 1 or auto"),
        };
        let providers = oidc::providers()?;
        ensure!(
            local || !providers.is_empty(),
            "Disabling local login requires an OIDC provider"
        );

        let origin = optional_env("CERTHIA_AUTH_ORIGIN")
            .map(|s| Url::parse(&s))
            .transpose()
            .context("Invalid CERTHIA_AUTH_ORIGIN")?;
        if let Some(url) = &origin {
            ensure!(
                url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.host_str().is_some_and(|host| allowed_hosts
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(host)))
                    && (mixed || url.scheme() == if secure { "https" } else { "http" }),
                "CERTHIA_AUTH_ORIGIN must be an origin covered by CERTHIA_ALLOWED_HOSTS and match the cookie security setting"
            );
        }
        if !secure && !mixed {
            ensure!(
                allowed_hosts.iter().all(|host| access::loopback(host)),
                "Insecure cookies require loopback-only CERTHIA_ALLOWED_HOSTS"
            );
        }
        ensure!(
            providers.is_empty() || origin.is_some(),
            "OIDC requires CERTHIA_AUTH_ORIGIN"
        );

        let trusted_proxies = optional_env("CERTHIA_AUTH_TRUSTED_PROXIES")
            .map(|s| {
                s.split(',')
                    .map(|ip| ip.trim().parse::<IpAddr>().map(|ip| ip.to_canonical()))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()
            .context("CERTHIA_AUTH_TRUSTED_PROXIES must contain literal IP addresses")?
            .unwrap_or_default();
        // Setup is open until the first administrator exists. A configured token
        // additionally gates it for deployments reachable before setup completes.
        let setup_code = if local {
            secret_env("CERTHIA_SETUP_TOKEN")?
        } else {
            None
        };
        if let Some(code) = &setup_code {
            ensure!(
                code.len() >= 32 && code.len() <= 512 && !code.chars().any(char::is_control),
                "CERTHIA_SETUP_TOKEN must contain 32–512 characters without control characters"
            );
        }
        let config = Self {
            local,
            secure,
            mixed,
            origin,
            trusted_proxies,
            setup_hash: setup_code.as_ref().map(|code| hash(code.as_bytes())),
            providers,
            oidc_http: oidc::http_client()?,
            dummy_hash: accounts::password_hash(&random_token()?)?,
            password_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        };
        Ok(Startup { config })
    }

    fn cookie_name(&self, name: &'static str) -> String {
        format!("{}{name}", if self.secure { "__Host-" } else { "" })
    }

    fn cookie(&self, name: &'static str, value: &str, max_age: u64) -> String {
        format!(
            "{}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax{}",
            self.cookie_name(name),
            if self.secure { "; Secure" } else { "" }
        )
    }
}

pub fn routes() -> Router<App> {
    Router::new()
        .route("/auth/status", get(accounts::status))
        .route("/auth/setup", post(accounts::setup))
        .route("/auth/login", post(accounts::login))
        .route("/auth/me", get(accounts::me))
        .route("/auth/logout", post(accounts::logout))
        .route("/auth/password", put(accounts::change_password))
        .route("/auth/oidc/{provider}/start", post(oidc::start))
        .route("/auth/oidc/{provider}/callback", get(oidc::callback))
        .route(
            "/settings/sso",
            get(workspace_sso::get).put(workspace_sso::save),
        )
        .route("/users", get(accounts::list).post(accounts::create))
        .route("/users/{id}", put(accounts::update))
        .route("/users/{id}/sessions/revoke", post(accounts::revoke))
        .layer(DefaultBodyLimit::max(16 * 1024))
}

pub async fn cleanup(pool: PgPool) {
    loop {
        for statement in [
            "DELETE FROM auth_sessions WHERE idle_expires <= now()",
            "DELETE FROM auth_rate_limits WHERE expires <= now()",
            "DELETE FROM auth_oidc_flows WHERE expires <= now()",
        ] {
            if let Err(error) = sqlx::query(statement).execute(&pool).await {
                tracing::warn!(%error, "Could not remove expired authentication data");
            }
        }
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

fn flag(name: &str, default: bool) -> Result<bool> {
    match optional_env(name).as_deref() {
        Some("0") => Ok(false),
        Some("1") => Ok(true),
        None => Ok(default),
        Some(_) => bail!("{name} must be 0 or 1"),
    }
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

fn secret_env(name: &str) -> Result<Option<String>> {
    match (optional_env(name), optional_env(&format!("{name}_FILE"))) {
        (Some(_), Some(_)) => bail!("Configure only one of {name} and {name}_FILE"),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => {
            let value =
                std::fs::read_to_string(path).with_context(|| format!("Read {name}_FILE"))?;
            let value = value.trim_end_matches(['\r', '\n']);
            ensure!(!value.is_empty(), "{name}_FILE is empty");
            Ok(Some(value.to_owned()))
        }
        (None, None) => Ok(None),
    }
}

fn hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn random_bytes() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("System randomness unavailable"))?;
    Ok(bytes)
}

fn random_token() -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes()?))
}

fn token_hash(token: &str) -> Option<[u8; 32]> {
    if token.len() != 43 {
        return None;
    }
    let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(token).ok()?.try_into().ok()?;
    Some(hash(&bytes))
}

fn unauthorized() -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, "Sign-in required.".into())
}

fn forbidden() -> ApiError {
    ApiError(
        StatusCode::FORBIDDEN,
        "You don't have permission to do that.".into(),
    )
}

async fn audit(
    connection: &mut sqlx::PgConnection,
    action: &str,
    user: Option<Uuid>,
    actor: Option<Uuid>,
    detail: &str,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO audit_events(action,resource,detail,actor_user_id) VALUES($1,$2,$3,$4)",
    )
    .bind(action)
    .bind(
        user.map(|id| id.to_string())
            .unwrap_or_else(|| "auth".into()),
    )
    .bind(detail)
    .bind(actor)
    .execute(connection)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn api_router_applies_session_csrf_and_machine_policies() {
        use axum::{
            body::Body,
            http::{Request, header},
            middleware,
        };
        use tower::ServiceExt;

        let directory = tempfile::tempdir().unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://unused@127.0.0.1/unused")
            .unwrap();
        let app = App(std::sync::Arc::new(crate::AppState {
            database: crate::postgres::Database {
                primary: pool.clone(),
                reads: pool,
            },
            vault: crate::scanner::Vault::open(&directory.path().join("registry.key")).unwrap(),
            cache: directory.path().to_owned(),
            work: tokio::sync::Notify::new(),
            progress: tokio::sync::broadcast::channel(1).0,
            patch_slot: tokio::sync::Semaphore::new(1),
            data: directory.path().to_owned(),
            allowed_hosts: vec!["certhia.example".into()],
            auth: Config {
                local: true,
                secure: true,
                mixed: false,
                origin: Some(Url::parse("https://certhia.example").unwrap()),
                trusted_proxies: Vec::new(),
                setup_hash: None,
                providers: Vec::new(),
                oidc_http: oidc::http_client().unwrap(),
                dummy_hash: String::new(),
                password_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            },
        }));
        let token = random_token().unwrap();
        let cookie = app
            .0
            .auth
            .cookie(access::SESSION, &token, access::SESSION_SECONDS);
        assert_eq!(
            cookie,
            format!(
                "__Host-certhia_session={token}; Path=/; Max-Age=43200; HttpOnly; SameSite=Lax; Secure"
            )
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!("__Host-certhia_session={token}").parse().unwrap(),
        );
        assert_eq!(
            access::cookie_token(&headers, "__Host-certhia_session"),
            token_hash(&token)
        );
        headers.append(
            header::COOKIE,
            format!("__Host-certhia_session={token}").parse().unwrap(),
        );
        assert_eq!(
            access::cookie_token(&headers, "__Host-certhia_session"),
            None
        );

        let router = Router::new()
            .nest(
                "/api",
                crate::api_routes().layer(middleware::from_fn_with_state(app.clone(), authorize)),
            )
            .layer(middleware::from_fn_with_state(
                app.clone(),
                crate::local_requests,
            ))
            .with_state(app);
        let response = |method: &str, path: &str, origin: Option<&str>| {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, "certhia.example");
            if let Some(origin) = origin {
                request = request.header(header::ORIGIN, origin);
            }
            let mut request = request.body(Body::empty()).unwrap();
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                "127.0.0.1:54321".parse::<std::net::SocketAddr>().unwrap(),
            ));
            router.clone().oneshot(request)
        };

        assert_eq!(
            response("GET", "/api/health", None).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            response("GET", "/api/scans", None).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            response("PUT", "/api/settings", None)
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            response("POST", "/api/auth/login", None)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            response("POST", "/api/auth/login", Some("https://bad.example"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            response("POST", "/api/auth/login", Some("https://certhia.example"))
                .await
                .unwrap()
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn session_tokens_are_random_and_hash_canonical_256_bit_values() {
        let token = random_token().unwrap();
        let first = token_hash(&token).unwrap();
        assert_ne!(first, token_hash(&random_token().unwrap()).unwrap());
        assert_ne!(first.as_slice(), URL_SAFE_NO_PAD.decode(&token).unwrap());
        assert_eq!(token_hash(&format!("{token}=")), None);
        assert_eq!(token_hash("invalid"), None);
    }
}
