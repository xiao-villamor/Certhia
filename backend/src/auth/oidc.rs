use super::{
    Role, User,
    access::{client_ip, cookie_token, issue_session},
    accounts::{email, insert_user, lock_user, lock_users, name, rate_limit, user_by_email},
    audit, forbidden, hash, random_token, secret_env, token_hash, workspace_sso,
};
use crate::{ApiError, ApiResult, App};
use anyhow::{Context, Result, ensure};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, header},
    response::{AppendHeaders, IntoResponse, Redirect, Response},
};
use openidconnect::{
    AdditionalClaims, AuthType, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdTokenClaims,
    IdTokenFields, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    StandardErrorResponse, StandardTokenResponse, core::*,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgConnection;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    time::Duration,
};
use url::Url;
use uuid::Uuid;

const FLOW_COOKIE: &str = "certhia_oidc";
const FLOW_SECONDS: u64 = 600;

pub type HttpClient = openidconnect::reqwest::Client;

type TokenFields = IdTokenFields<
    Claims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;
type OidcClient = Client<
    Claims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    StandardTokenResponse<TokenFields, CoreTokenType>,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Claims(BTreeMap<String, Value>);
impl AdditionalClaims for Claims {}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Provider {
    pub id: String,
    pub name: String,
    issuer: String,
    client_id: String,
    client_secret_env: Option<String>,
    #[serde(skip)]
    client_secret: String,
    #[serde(default)]
    secret_post: bool,
    #[serde(default)]
    pub link_by_email: bool,
    #[serde(default)]
    trust_email: bool,
    #[serde(default)]
    allowed_domains: Vec<String>,
    #[serde(default)]
    jit: bool,
    role_claim: Option<String>,
    #[serde(default)]
    required_claims: BTreeMap<String, String>,
    #[serde(default)]
    role_map: BTreeMap<String, Role>,
    #[serde(default = "viewer")]
    default_role: Role,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(skip)]
    workspace_revision: Option<Uuid>,
}

impl Provider {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn workspace(
        settings: workspace_sso::Settings,
        client_secret: String,
        revision: Uuid,
    ) -> Self {
        Self {
            id: workspace_sso::ID.into(),
            name: settings.name,
            issuer: settings.issuer,
            client_id: settings.client_id,
            client_secret_env: None,
            client_secret,
            secret_post: settings.secret_post,
            link_by_email: true,
            trust_email: settings.trust_email,
            allowed_domains: settings.allowed_domains,
            jit: settings.jit,
            role_claim: None,
            required_claims: BTreeMap::new(),
            role_map: BTreeMap::new(),
            default_role: Role::Viewer,
            scopes: Vec::new(),
            workspace_revision: Some(revision),
        }
    }

    fn flow_key(&self) -> String {
        self.workspace_revision.map_or_else(
            || self.id.clone(),
            |revision| format!("{}:{revision}", self.id),
        )
    }
}

fn viewer() -> Role {
    Role::Viewer
}

pub fn providers() -> Result<Vec<Provider>> {
    let Some(config) = secret_env("CERTHIA_OIDC_PROVIDERS")? else {
        return Ok(Vec::new());
    };
    let mut providers: Vec<Provider> =
        serde_json::from_str(&config).context("Invalid OIDC provider JSON")?;
    let mut ids = BTreeSet::new();
    let mut issuers = BTreeSet::new();
    for provider in &mut providers {
        ensure!(
            !provider.id.is_empty()
                && provider.id.len() <= 40
                && provider
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && ids.insert(provider.id.clone()),
            "OIDC provider IDs must be unique and contain 1–40 lowercase letters, digits, or dashes"
        );
        parse_issuer(&provider.issuer)?;
        ensure!(
            issuers.insert(provider.issuer.clone()),
            "OIDC issuers must be unique"
        );
        name(&provider.name)?;
        ensure!(
            !provider.client_id.trim().is_empty(),
            "OIDC client ID is required"
        );
        let variable = provider.client_secret_env.clone().unwrap_or_else(|| {
            format!(
                "CERTHIA_OIDC_{}_CLIENT_SECRET",
                provider.id.to_uppercase().replace('-', "_")
            )
        });
        ensure!(
            !variable.is_empty()
                && variable
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                && !variable.ends_with("_FILE"),
            "OIDC clientSecretEnv must be an environment variable name without the _FILE suffix"
        );
        provider.client_secret =
            secret_env(&variable)?.with_context(|| format!("Set {variable} or {variable}_FILE"))?;
        for domain in &mut provider.allowed_domains {
            *domain = normalize_domain(domain)?;
        }
        ensure!(
            !provider.jit || !provider.allowed_domains.is_empty(),
            "OIDC just-in-time provisioning requires at least one allowed domain"
        );
        ensure!(
            provider.role_map.is_empty()
                || provider
                    .role_claim
                    .as_ref()
                    .is_some_and(|claim| !claim.is_empty()),
            "OIDC roleMap requires a roleClaim"
        );
    }
    Ok(providers)
}

pub fn normalize_domain(domain: &str) -> Result<String> {
    let address = email(&format!("user@{domain}")).context("Enter valid allowed email domains.")?;
    Ok(address.split_once('@').expect("validated email").1.into())
}

pub fn parse_issuer(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("Enter a valid OIDC issuer URL.")?;
    ensure!(
        https_endpoint(&url) && url.query().is_none(),
        "Use an HTTPS issuer URL without credentials, query, or fragment."
    );
    Ok(url)
}

fn https_endpoint(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

pub fn http_client() -> Result<HttpClient> {
    Ok(HttpClient::builder()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .https_only(true)
        .no_proxy()
        .timeout(Duration::from_secs(8))
        .build()?)
}

async fn client(app: &App, provider: &Provider, origin: &Url) -> Result<OidcClient> {
    // Rediscover on callback as well as start so a signing-key rotation during login is handled.
    let metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(provider.issuer.clone())?,
        &app.0.auth.oidc_http,
    )
    .await?;
    ensure!(
        https_endpoint(metadata.authorization_endpoint().url())
            && metadata
                .token_endpoint()
                .is_some_and(|url| https_endpoint(url.url()))
            && https_endpoint(metadata.jwks_uri().url()),
        "OIDC discovery returned invalid HTTPS endpoints"
    );
    let redirect = workspace_sso::callback_url(origin, &provider.id);
    Ok(OidcClient::from_provider_metadata(
        metadata,
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(provider.client_secret.clone())),
    )
    .set_auth_type(if provider.secret_post {
        AuthType::RequestBody
    } else {
        AuthType::BasicAuth
    })
    .set_redirect_uri(RedirectUrl::from_url(redirect)))
}

async fn provider(app: &App, id: &str) -> ApiResult<Provider> {
    if let Some(provider) = app
        .0
        .auth
        .providers
        .iter()
        .find(|provider| provider.id == id)
    {
        return Ok(provider.clone());
    }
    if id == workspace_sso::ID
        && let Some(row) = workspace_sso::active(app).await?
    {
        return row.into_provider(app);
    }
    Err(ApiError::missing("Sign-in provider not found."))
}

pub async fn start(
    State(app): State<App>,
    Path(id): Path<String>,
    peer: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let origin = workspace_sso::origin(&app, &headers).ok_or_else(forbidden)?;
    let provider = provider(&app, &id).await?;
    if provider.workspace_revision.is_some()
        && headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            != Some(origin.origin().ascii_serialization().as_str())
    {
        return Err(forbidden());
    }
    let pool = &app.0.database.primary;
    rate_limit(
        pool,
        "oidc-ip",
        &client_ip(&app, peer, &headers).to_string(),
        30,
    )
    .await?;
    let client = match client(&app, &provider, &origin).await {
        Ok(client) => client,
        Err(_) => return failed(&app, &provider, "discovery").await,
    };
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge)
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()));
    for scope in &provider.scopes {
        request = request.add_scope(Scope::new(scope.clone()));
    }
    let (url, state, nonce) = request.url();
    let browser = random_token()?;
    let browser_hash = token_hash(&browser).expect("generated token is canonical");
    sqlx::query("INSERT INTO auth_oidc_flows(state_hash,browser_hash,provider,verifier,nonce) VALUES($1,$2,$3,$4,$5)")
        .bind(hash(state.secret().as_bytes()).as_slice()).bind(browser_hash.as_slice())
        .bind(provider.flow_key()).bind(verifier.secret()).bind(nonce.secret()).execute(pool).await?;
    Ok((
        [(
            header::SET_COOKIE,
            app.0.auth.cookie(FLOW_COOKIE, &browser, FLOW_SECONDS),
        )],
        Redirect::to(url.as_str()),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct Callback {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
    iss: Option<String>,
}

pub async fn callback(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<Callback>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let origin = workspace_sso::origin(&app, &headers).ok_or_else(forbidden)?;
    let provider = provider(&app, &id).await?;
    let (Some(state), Some(browser_hash)) = (
        query.state,
        cookie_token(&headers, &app.0.auth.cookie_name(FLOW_COOKIE)),
    ) else {
        return Ok(Redirect::to("/login?error=oidc").into_response());
    };
    let pool = &app.0.database.primary;
    let flow: Option<(String, String)> = sqlx::query_as(
        "DELETE FROM auth_oidc_flows WHERE state_hash=$1 AND browser_hash=$2 AND provider=$3 AND expires>now()
         RETURNING verifier,nonce",
    )
    .bind(hash(state.as_bytes()).as_slice()).bind(browser_hash.as_slice()).bind(provider.flow_key())
    .fetch_optional(pool).await?;
    let Some((verifier, nonce)) = flow else {
        return Ok(Redirect::to("/login?error=oidc").into_response());
    };
    let Some(code) = query.code.filter(|_| {
        query.error.is_none() && query.iss.is_none_or(|issuer| issuer == provider.issuer)
    }) else {
        return failed(&app, &provider, "provider rejected authorization").await;
    };
    let claims = match exchange(&app, &provider, &origin, code, verifier, nonce).await {
        Ok(claims) => claims,
        Err(_) => return failed(&app, &provider, "token exchange or validation").await,
    };
    let identity = Identity {
        subject: claims.subject().as_str(),
        email: claims.email().map(|email| email.as_str()),
        verified: claims.email_verified(),
        name: claims
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.as_str()),
        claims: &claims.additional_claims().0,
    };
    let mut tx = pool.begin().await?;
    lock_users(&mut tx).await?;
    if let Some(revision) = provider.workspace_revision
        && !workspace_sso::revision_active(&mut tx, revision).await?
    {
        return Ok(Redirect::to("/login?error=oidc").into_response());
    }
    let Some(user) = resolve_user(&mut tx, &provider, &identity).await? else {
        tx.rollback().await?;
        return failed(&app, &provider, "account access denied").await;
    };
    let cookie = issue_session(
        &app,
        &mut tx,
        &headers,
        &user,
        &format!("oidc:{}", provider.id),
    )
    .await?;
    tx.commit().await?;
    Ok(completed_login(
        cookie,
        app.0.auth.cookie(FLOW_COOKIE, "", 0),
    ))
}

fn completed_login(session: String, expired_flow: String) -> Response {
    (
        AppendHeaders([
            (header::SET_COOKIE, session),
            (header::SET_COOKIE, expired_flow),
        ]),
        Redirect::to("/"),
    )
        .into_response()
}

async fn exchange(
    app: &App,
    provider: &Provider,
    origin: &Url,
    code: String,
    verifier: String,
    nonce: String,
) -> Result<IdTokenClaims<Claims, CoreGenderClaim>> {
    let client = client(app, provider, origin).await?;
    let response = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&app.0.auth.oidc_http)
        .await?;
    let token = response
        .extra_fields()
        .id_token()
        .context("Missing ID token")?;
    let claims = token.claims(&client.id_token_verifier(), &Nonce::new(nonce))?;
    ensure!(
        accepts_claims(provider, &claims.additional_claims().0),
        "ID token did not satisfy the provider's required claims"
    );
    ensure!(
        claims
            .authorized_party()
            .is_none_or(|party| party.as_str() == provider.client_id),
        "ID token authorized party did not match the configured client"
    );
    Ok(claims.clone())
}

async fn failed(app: &App, provider: &Provider, stage: &str) -> ApiResult<Response> {
    let detail = format!("oidc:{} ({stage})", provider.id);
    audit(
        &mut *app.0.database.primary.acquire().await?,
        "auth.login.failed",
        None,
        None,
        &detail,
    )
    .await?;
    Ok((
        [(header::SET_COOKIE, app.0.auth.cookie(FLOW_COOKIE, "", 0))],
        Redirect::to("/login?error=oidc"),
    )
        .into_response())
}

struct Identity<'a> {
    subject: &'a str,
    email: Option<&'a str>,
    verified: Option<bool>,
    name: Option<&'a str>,
    claims: &'a BTreeMap<String, Value>,
}

fn verified_email(provider: &Provider, identity: &Identity<'_>) -> Option<String> {
    if !identity.verified.unwrap_or(provider.trust_email) {
        return None;
    }
    let email = email(identity.email?).ok()?;
    let (_, domain) = email.split_once('@')?;
    (provider.allowed_domains.is_empty()
        || provider
            .allowed_domains
            .iter()
            .any(|allowed| allowed == domain))
    .then_some(email)
}

fn accepts_claims(provider: &Provider, claims: &BTreeMap<String, Value>) -> bool {
    provider
        .required_claims
        .iter()
        .all(|(key, required)| claims.get(key).and_then(Value::as_str) == Some(required.as_str()))
}

fn mapped_role(provider: &Provider, claims: &BTreeMap<String, Value>) -> Role {
    let Some(value) = provider.role_claim.as_ref().and_then(|key| claims.get(key)) else {
        return provider.default_role;
    };
    let role = |name: &str| provider.role_map.get(name).copied();
    match value {
        Value::String(name) => role(name),
        Value::Array(values) if values.iter().all(Value::is_string) => values
            .iter()
            .filter_map(|value| value.as_str().and_then(role))
            .max(),
        _ => None,
    }
    .unwrap_or(provider.default_role)
}

async fn resolve_user(
    connection: &mut PgConnection,
    provider: &Provider,
    identity: &Identity<'_>,
) -> ApiResult<Option<User>> {
    if identity.subject.is_empty() || identity.subject.len() > 255 {
        return Ok(None);
    }
    let id: Option<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM auth_identities WHERE issuer=$1 AND subject=$2")
            .bind(&provider.issuer)
            .bind(identity.subject)
            .fetch_optional(&mut *connection)
            .await?;
    if let Some(id) = id {
        return Ok(lock_user(connection, id)
            .await?
            .filter(|user| !user.disabled));
    }
    let Some(email) = verified_email(provider, identity) else {
        return Ok(None);
    };
    let user = match user_by_email(connection, &email).await? {
        Some(user)
            if provider.link_by_email
                && !user.disabled
                && (provider.workspace_revision.is_none() || !user.has_password) =>
        {
            user
        }
        Some(_) => return Ok(None),
        None if provider.jit => {
            let display_name = identity
                .name
                .and_then(|value| name(value).ok())
                .unwrap_or_else(|| email.split_once('@').expect("validated email").0);
            let display_name: String = display_name.chars().take(100).collect();
            let user = insert_user(
                connection,
                &email,
                &display_name,
                mapped_role(provider, identity.claims),
                None,
            )
            .await?;
            audit(
                connection,
                "auth.oidc.provisioned",
                Some(user.id),
                Some(user.id),
                &provider.id,
            )
            .await?;
            user
        }
        None => return Ok(None),
    };
    let result = sqlx::query(
        "INSERT INTO auth_identities(issuer,subject,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
    ).bind(&provider.issuer).bind(identity.subject).bind(user.id).execute(&mut *connection).await?;
    if result.rows_affected() == 0 {
        return Ok(None);
    }
    audit(
        connection,
        "auth.oidc.linked",
        Some(user.id),
        Some(user.id),
        &provider.id,
    )
    .await?;
    Ok(Some(user))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn example() -> Provider {
        serde_json::from_value(json!({
            "id":"work", "name":"Work", "issuer":"https://id.example", "clientId":"certhia",
            "allowedDomains":["example.com"], "jit":true,
            "roleClaim":"groups", "roleMap":{"admins":"admin","scanners":"operator"}
        }))
        .unwrap()
    }

    #[test]
    fn successful_callback_sets_session_and_clears_flow_cookie() {
        let session = "__Host-certhia_session=new; Path=/";
        let flow = "__Host-certhia_oidc=; Path=/; Max-Age=0";
        let response = completed_login(session.into(), flow.into());
        let cookies: Vec<_> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(cookies, [session, flow]);
    }

    #[test]
    fn maps_only_signed_claim_values_with_explicit_group_matches() {
        let provider = example();
        for (claim, expected) in [
            (json!(["scanners", "admins"]), Role::Admin),
            (json!("scanners"), Role::Operator),
            (json!(["admins", 7]), Role::Viewer),
            (json!(["Admins"]), Role::Viewer),
            (json!([{"name":"admins"}]), Role::Viewer),
            (json!(null), Role::Viewer),
        ] {
            assert_eq!(
                mapped_role(&provider, &BTreeMap::from([("groups".into(), claim)])),
                expected
            );
        }
    }

    #[test]
    fn additional_claims_are_available_to_policy_and_require_exact_values() {
        let mut provider = example();
        provider
            .required_claims
            .insert("hd".into(), "example.com".into());
        let token: IdTokenClaims<Claims, CoreGenderClaim> = serde_json::from_value(json!({
            "iss":"https://id.example","aud":"certhia","sub":"some-user","exp":2000000000,
            "iat":1999990000,"nonce":"nonce","groups":["scanners"],"hd":"example.com"
        }))
        .unwrap();
        let claims = &token.additional_claims().0;
        assert!(accepts_claims(&provider, claims));
        assert_eq!(mapped_role(&provider, claims), Role::Operator);
        assert!(!accepts_claims(
            &provider,
            &BTreeMap::from([("hd".into(), json!(["example.com"]))])
        ));
        assert!(!accepts_claims(&provider, &BTreeMap::new()));
    }

    #[test]
    fn linking_email_must_be_verified_and_domain_match_exactly() {
        let mut provider = example();
        let claims = BTreeMap::new();
        let mut identity = Identity {
            subject: "abc",
            email: Some("User@EXAMPLE.COM"),
            verified: Some(true),
            name: None,
            claims: &claims,
        };
        assert_eq!(
            verified_email(&provider, &identity).as_deref(),
            Some("user@example.com")
        );
        identity.verified = None;
        assert!(verified_email(&provider, &identity).is_none());
        provider.trust_email = true;
        assert!(verified_email(&provider, &identity).is_some());
        identity.verified = Some(false);
        assert!(verified_email(&provider, &identity).is_none());
        identity.verified = Some(true);
        identity.email = Some("user@sub.example.com");
        assert!(verified_email(&provider, &identity).is_none());
    }
}
