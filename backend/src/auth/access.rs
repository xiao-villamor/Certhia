use super::{ACTOR, Role, User, forbidden, token_hash, unauthorized};
use crate::{ApiError, ApiResult, App};
use axum::{
    extract::{ConnectInfo, MatchedPath, Request, State},
    http::{HeaderMap, Method, header, uri::Authority},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::{IpAddr, SocketAddr};
use url::Url;

pub const SESSION: &str = "certhia_session";
const IDLE_MINUTES: i32 = 30;

#[derive(Clone)]
pub struct Session {
    pub user: User,
    pub hash: [u8; 32],
}

impl Session {
    pub async fn is_active<'a>(
        &self,
        db: impl sqlx::Executor<'a, Database = sqlx::Postgres>,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM auth_sessions WHERE token_hash=$1 AND idle_expires>now() AND expires>now())",
        )
        .bind(self.hash.as_slice()).fetch_one(db).await
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Access {
    Public,
    PublicMutation,
    Machine,
    Session(Role),
}

pub fn classify(method: &str, path: &str) -> Option<Access> {
    use Access::*;
    use Role::*;
    let access = match (method, path) {
        ("GET" | "HEAD", "/health" | "/ready" | "/version" | "/auth/status")
        | ("GET", "/auth/oidc/{provider}/callback") => Public,
        ("POST", "/auth/login" | "/auth/setup" | "/auth/oidc/{provider}/start") => PublicMutation,
        ("POST", "/webhooks/registries/{id}/ci" | "/webhooks/registries/{id}/harbor") => Machine,
        (
            "GET" | "HEAD",
            "/auth/me"
            | "/openapi.json"
            | "/dashboard"
            | "/scans"
            | "/scans/bulk"
            | "/scans/{id}"
            | "/scans/{id}/events"
            | "/scans/{id}/progress"
            | "/scans/{id}/classifications"
            | "/scans/{id}/watch"
            | "/scans/{id}/report/{format}"
            | "/scans/{id}/scanner-results"
            | "/scans/{id}/scanner-results/{tool}"
            | "/scans/{id}/finding-sources"
            | "/compare"
            | "/images"
            | "/images/{id}/archive"
            | "/images/{id}/layers"
            | "/images/{id}/layers/{index}/files"
            | "/vulnerabilities"
            | "/library/packages"
            | "/library/top-packages"
            | "/library/advisories"
            | "/library/advisories/{id}/digests"
            | "/advisories/{id}"
            | "/repositories/{id}/findings"
            | "/digests/{a}/compare/{b}"
            | "/scheduled-scans"
            | "/scheduled-scans/history"
            | "/image-watches"
            | "/patches/history"
            | "/patches/analyze/{id}"
            | "/patches/{id}/status"
            | "/patches/{id}/download"
            | "/settings/report-branding/logo",
        )
        | ("POST", "/auth/logout")
        | ("PUT", "/auth/password") => Session(Viewer),
        (
            "GET" | "HEAD",
            "/registries"
            | "/registries/{id}/catalog"
            | "/registries/{id}/tags"
            | "/discover/dockerhub"
            | "/discover/docker"
            | "/discover/swarm"
            | "/discover/kubernetes"
            | "/discover/kubernetes/namespaces"
            | "/config/raw-output"
            | "/scanners/available"
            | "/settings/issue-trackers",
        )
        | (
            "POST",
            "/scans"
            | "/scans/bulk"
            | "/scans/import"
            | "/scans/archive"
            | "/scans/{id}/rescan"
            | "/scans/{id}/cancel"
            | "/compare/plan"
            | "/images/{id}/publish"
            | "/patches/execute"
            | "/patches/{id}/publish"
            | "/scheduled-scans"
            | "/scheduled-scans/{id}/execute",
        )
        | ("PUT", "/scans/{id}/classifications" | "/scans/{id}/watch" | "/scheduled-scans/{id}")
        | ("DELETE", "/scheduled-scans/{id}" | "/image-watches/{id}") => Session(Operator),
        (
            "GET" | "HEAD",
            "/users"
            | "/settings"
            | "/settings/report-branding"
            | "/registries/{id}/webhook"
            | "/audit-logs",
        )
        | (
            "POST",
            "/users"
            | "/users/{id}/sessions/revoke"
            | "/registries"
            | "/registries/test"
            | "/registries/{id}/test"
            | "/registries/{id}/catalog"
            | "/registries/{id}/webhook"
            | "/settings/notifications/test"
            | "/settings/issue-trackers"
            | "/images/delete",
        )
        | (
            "PUT",
            "/users/{id}"
            | "/registries/{id}"
            | "/settings"
            | "/settings/scanners"
            | "/settings/report-branding"
            | "/settings/report-branding/logo"
            | "/settings/issue-trackers/{id}",
        )
        | (
            "DELETE",
            "/registries/{id}"
            | "/registries/{id}/webhook"
            | "/settings/report-branding/logo"
            | "/settings/issue-trackers/{id}",
        ) => Session(Admin),
        _ => return None,
    };
    Some(access)
}

pub async fn authorize(State(app): State<App>, mut request: Request, next: Next) -> Response {
    let access = request
        .extensions()
        .get::<MatchedPath>()
        .and_then(|path| path.as_str().strip_prefix("/api"))
        .and_then(|path| classify(request.method().as_str(), path));
    let error = match access {
        Some(Access::Public | Access::Machine) => return next.run(request).await,
        Some(Access::PublicMutation) => {
            if same_origin(&app.0.auth, request.headers()) {
                return next.run(request).await;
            }
            forbidden()
        }
        access => {
            let session = authenticate(&app, request.headers()).await;
            match (session, access) {
                (Err(error), _) => error,
                (Ok(session), Some(Access::Session(role))) if session.user.role >= role => {
                    let headers = request.headers();
                    let cross_origin = headers
                        .get("sec-fetch-site")
                        .is_some_and(|site| site != "same-origin" && site != "none");
                    let mutation =
                        request.method() != Method::GET && request.method() != Method::HEAD;
                    if cross_origin || (mutation && !same_origin(&app.0.auth, headers)) {
                        return forbidden().into_response();
                    }
                    let actor = session.user.id;
                    request.extensions_mut().insert(session);
                    return ACTOR.scope(actor, next.run(request)).await;
                }
                (Ok(_), Some(_)) => forbidden(),
                (Ok(_), None) => ApiError::missing("Endpoint not found."),
            }
        }
    };
    error.into_response()
}

async fn authenticate(app: &App, headers: &HeaderMap) -> ApiResult<Session> {
    let hash = cookie_token(headers, &app.0.auth.cookie_name(SESSION)).ok_or_else(unauthorized)?;
    let pool = &app.0.database.primary;
    let user = sqlx::query_as::<_, User>(
        "SELECT u.id,u.email,u.display_name,u.role,u.disabled,u.password_hash IS NOT NULL AS has_password
         FROM auth_sessions s JOIN auth_users u ON u.id=s.user_id
         WHERE s.token_hash=$1 AND s.idle_expires>now() AND s.expires>now() AND NOT u.disabled",
    )
    .bind(hash.as_slice()).fetch_optional(pool).await?.ok_or_else(unauthorized)?;
    sqlx::query(
        "UPDATE auth_sessions SET idle_expires=LEAST(expires,now()+make_interval(mins=>$2))
         WHERE token_hash=$1 AND expires>now() AND idle_expires>now()
         AND idle_expires<LEAST(expires,now()+make_interval(mins=>$2))-interval '1 minute'",
    )
    .bind(hash.as_slice())
    .bind(IDLE_MINUTES)
    .execute(pool)
    .await?;
    Ok(Session { user, hash })
}

pub fn cookie_token(headers: &HeaderMap, name: &str) -> Option<[u8; 32]> {
    let mut values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|header| header.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .filter(|(key, _)| *key == name);
    let (_, value) = values.next()?;
    if values.next().is_some() {
        return None;
    }
    token_hash(value)
}

pub fn loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

pub fn host(headers: &HeaderMap) -> Option<Authority> {
    single_header(headers, header::HOST)?.parse().ok()
}

fn single_header(headers: &HeaderMap, name: impl axum::http::header::AsHeaderName) -> Option<&str> {
    let entries = headers.get_all(name);
    let mut values = entries.iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

fn same_origin(config: &super::Config, headers: &HeaderMap) -> bool {
    let Some(authority) = host(headers) else {
        return false;
    };
    let Some(origin) = single_header(headers, header::ORIGIN) else {
        return false;
    };
    let scheme = if config.secure { "https" } else { "http" };
    origin_matches(origin, scheme, &authority, config.origin.as_ref())
}

fn origin_matches(origin: &str, scheme: &str, host: &Authority, configured: Option<&Url>) -> bool {
    let Ok(target) = Url::parse(&format!("{scheme}://{host}/")) else {
        return false;
    };
    // A browser Origin header contains the canonical serialized origin and no path.
    let expected = target.origin().ascii_serialization();
    origin == expected && configured.is_none_or(|public| public.origin() == target.origin())
}

pub fn client_ip(app: &App, peer: ConnectInfo<SocketAddr>, headers: &HeaderMap) -> IpAddr {
    let ip = peer.0.ip().to_canonical();
    if app.0.auth.trusted_proxies.contains(&ip)
        && let Some(forwarded) =
            single_header(headers, "x-real-ip").and_then(|s| s.parse::<IpAddr>().ok())
    {
        return forwarded.to_canonical();
    }
    ip
}

pub const SESSION_SECONDS: u64 = 12 * 60 * 60;

pub async fn issue_session(
    app: &App,
    tx: &mut sqlx::PgConnection,
    headers: &HeaderMap,
    user: &User,
    method: &str,
) -> ApiResult<String> {
    if let Some(old) = cookie_token(headers, &app.0.auth.cookie_name(SESSION)) {
        sqlx::query("DELETE FROM auth_sessions WHERE token_hash=$1")
            .bind(old.as_slice())
            .execute(&mut *tx)
            .await?;
    }
    let token = super::random_token()?;
    let hash = token_hash(&token).expect("generated token is canonical");
    sqlx::query(
        "INSERT INTO auth_sessions(token_hash,user_id,idle_expires,expires)
        VALUES($1,$2,now()+make_interval(mins=>$3),now()+make_interval(secs=>$4))",
    )
    .bind(hash.as_slice())
    .bind(user.id)
    .bind(IDLE_MINUTES)
    .bind(SESSION_SECONDS as f64)
    .execute(&mut *tx)
    .await?;
    super::audit(
        tx,
        "auth.login.succeeded",
        Some(user.id),
        Some(user.id),
        method,
    )
    .await?;
    Ok(app.0.auth.cookie(SESSION, &token, SESSION_SECONDS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_origin_matches_only_public_scheme_and_authority() {
        let host = "certhia.example:8443".parse().unwrap();
        let public = Url::parse("https://certhia.example:8443").unwrap();
        assert!(origin_matches(
            "https://certhia.example:8443",
            "https",
            &host,
            Some(&public)
        ));
        for origin in [
            "null",
            "http://certhia.example:8443",
            "https://certhia.example",
            "https://certhia.example:8443/path",
            "https://evil.example",
            "https://certhia.example:8443.evil.test",
        ] {
            assert!(!origin_matches(origin, "https", &host, Some(&public)));
        }
        let other = "elsewhere.example".parse().unwrap();
        assert!(!origin_matches(
            "https://elsewhere.example",
            "https",
            &other,
            Some(&public)
        ));
        assert!(loopback("[::1]"));
        assert!(!loopback("localhost.example"));
    }

    #[test]
    fn role_order_and_method_specific_route_classification() {
        assert!(Role::Admin > Role::Operator && Role::Operator > Role::Viewer);
        assert_eq!(classify("GET", "/ready"), Some(Access::Public));
        assert_eq!(
            classify("POST", "/auth/login"),
            Some(Access::PublicMutation)
        );
        assert_eq!(
            classify("POST", "/webhooks/registries/{id}/ci"),
            Some(Access::Machine)
        );
        assert_eq!(classify("HEAD", "/auth/oidc/{provider}/callback"), None);
        assert_eq!(
            classify("GET", "/scans/{id}/classifications"),
            Some(Access::Session(Role::Viewer))
        );
        assert_eq!(
            classify("PUT", "/scans/{id}/classifications"),
            Some(Access::Session(Role::Operator))
        );
        assert_eq!(
            classify("POST", "/registries/{id}/catalog"),
            Some(Access::Session(Role::Admin))
        );
        assert_eq!(
            classify("POST", "/users/{id}/sessions/revoke"),
            Some(Access::Session(Role::Admin))
        );
        assert_eq!(classify("PUT", "/scans"), None);
    }
}
