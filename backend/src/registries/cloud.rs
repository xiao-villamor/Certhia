use super::{Client, Credentials, Result, Url, anyhow, bail, client};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use regex::Regex;
use ring::{digest, hmac};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::LazyLock,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub(super) const MARKER: &str = "_workload_identity";
pub(super) const ACR_USER: &str = "00000000-0000-0000-0000-000000000000";

// The public marker is accepted only when saving a validated profile. The
// scanner also accepts unsaved credentials and insecure transport options, so
// only the profile lookup can authorize a workload credential request there.
static SCANNER_MARKER: LazyLock<Option<String>> = LazyLock::new(|| {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0; 32];
    SystemRandom::new().fill(&mut bytes).ok()?;
    Some(URL_SAFE_NO_PAD.encode(bytes))
});

pub(super) fn scanner_marker() -> Result<Credentials> {
    let marker = SCANNER_MARKER
        .as_ref()
        .ok_or_else(|| anyhow!("Could not initialize workload identity."))?;
    Ok(Credentials {
        username: MARKER.into(),
        password: marker.clone(),
    })
}

pub(super) fn is_scanner_marker(auth: &Credentials) -> bool {
    use subtle::ConstantTimeEq;
    auth.username == MARKER
        && SCANNER_MARKER
            .as_ref()
            .is_some_and(|marker| bool::from(auth.password.as_bytes().ct_eq(marker.as_bytes())))
}

#[derive(Clone, Copy)]
pub(super) enum Provider {
    Ecr,
    Acr,
}

static ECR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[0-9]{12}\.dkr\.ecr\.([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\.(amazonaws\.com(?:\.cn)?)$",
    )
    .unwrap()
});
static ACR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{3,79}\.azurecr\.io$").unwrap());

pub(super) fn provider(host: &str) -> Result<Provider> {
    if ECR.is_match(host) {
        return Ok(Provider::Ecr);
    }
    if ACR.is_match(host) {
        return Ok(Provider::Acr);
    }
    bail!("Workload identity requires a standard private ECR or Azure public-cloud ACR login host.")
}

impl Provider {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Ecr => "ecr",
            Self::Acr => "acr",
        }
    }
}

struct Lease {
    auth: Credentials,
    refresh_at: Instant,
}

impl Lease {
    fn new(auth: Credentials, expires_at: DateTime<Utc>) -> Result<Self> {
        let remaining = (expires_at - Utc::now()).to_std().unwrap_or_default();
        let usable = remaining.saturating_sub(Duration::from_secs(120));
        anyhow::ensure!(
            !usable.is_zero(),
            "The provider returned a registry token too close to expiry."
        );
        Ok(Self {
            auth,
            // Bound retention and use a monotonic clock for cache hits.
            refresh_at: Instant::now() + usable.min(Duration::from_secs(3600)),
        })
    }

    fn current(&self) -> bool {
        Instant::now() < self.refresh_at
    }
}

// Cloud workload identity belongs to the server deployment. Credentials are per
// login host and never written to the registry profile or catalog.
static CACHE: LazyLock<Mutex<HashMap<String, Lease>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) async fn resolve(host: &str) -> Result<Credentials> {
    let provider = provider(host)?;
    {
        let mut cache = CACHE.lock().await;
        cache.retain(|_, lease| lease.current());
        if let Some(lease) = cache.get(host) {
            return Ok(lease.auth.clone());
        }
    }
    let http = client(false)?;
    let lease = match provider {
        Provider::Ecr => ecr(&http, host).await?,
        Provider::Acr => acr(&http, host).await?,
    };
    let auth = lease.auth.clone();
    let mut cache = CACHE.lock().await;
    if cache.len() < 64 {
        cache.insert(host.to_owned(), lease);
    }
    Ok(auth)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AwsSession {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: DateTime<Utc>,
}

fn aws_metadata_url(relative: Option<&str>, full: Option<&str>) -> Result<Url> {
    if let Some(path) = relative {
        anyhow::ensure!(
            path.starts_with('/') && !path.starts_with("//"),
            "Invalid ECS credential path."
        );
        let url = Url::parse(&format!("http://169.254.170.2{path}"))?;
        anyhow::ensure!(url.fragment().is_none(), "Invalid ECS credential path.");
        return Ok(url);
    }
    let full = full.ok_or_else(|| {
        anyhow!("Configure an ECS task role or EKS Pod Identity for the Certhia server.")
    })?;
    let url = Url::parse(full).map_err(|_| anyhow!("Invalid EKS Pod Identity endpoint."))?;
    anyhow::ensure!(
        url.scheme() == "http"
            && matches!(url.host_str(), Some("169.254.170.23" | "[fd00:ec2::23]"))
            && url.port().is_none()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "Use the EKS Pod Identity link-local credential endpoint."
    );
    Ok(url)
}

async fn aws_session() -> Result<AwsSession> {
    let relative = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").ok();
    let full = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI").ok();
    let url = aws_metadata_url(relative.as_deref(), full.as_deref())?;
    let http = Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut request = http.get(url);
    if relative.is_none() {
        let file = std::env::var_os("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
            .ok_or_else(|| anyhow!("The EKS Pod Identity authorization token file is missing."))?;
        let token = tokio::fs::read_to_string(file)
            .await
            .map_err(|_| anyhow!("Could not read the EKS Pod Identity authorization token."))?;
        request = request.header(reqwest::header::AUTHORIZATION, token.trim());
    }
    let session: AwsSession = exchange(request, "AWS workload credential endpoint").await?;
    anyhow::ensure!(
        session.expiration > Utc::now() && !session.token.is_empty(),
        "AWS workload credentials are missing or expired."
    );
    Ok(session)
}

const ECR_TARGET: &str = "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken";

fn signed_ecr(
    http: &Client,
    region: &str,
    endpoint: &str,
    now: DateTime<Utc>,
    session: &AwsSession,
) -> reqwest::RequestBuilder {
    let payload = "{}";
    let timestamp = now.format("%Y%m%dT%H%M%SZ");
    let date = now.format("%Y%m%d");
    let names = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";
    let headers = format!(
        "content-type:application/x-amz-json-1.1\nhost:{endpoint}\nx-amz-date:{timestamp}\nx-amz-security-token:{}\nx-amz-target:{ECR_TARGET}\n",
        session.token
    );
    let scope = format!("{date}/{region}/ecr/aws4_request");
    let canonical = format!(
        "POST\n/\n\n{headers}\n{names}\n{}",
        hash(payload.as_bytes())
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
        hash(canonical.as_bytes())
    );
    let sign = |key: &[u8], data: &str| {
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data.as_bytes())
    };
    let key = sign(
        format!("AWS4{}", session.secret_access_key).as_bytes(),
        &date.to_string(),
    );
    let key = sign(key.as_ref(), region);
    let key = sign(key.as_ref(), "ecr");
    let key = sign(key.as_ref(), "aws4_request");
    let signature = hex(sign(key.as_ref(), &to_sign).as_ref());
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={signature}",
        session.access_key_id
    );
    http.post(format!("https://{endpoint}/"))
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::CONTENT_TYPE, "application/x-amz-json-1.1")
        .header("x-amz-date", timestamp.to_string())
        .header("x-amz-security-token", &session.token)
        .header("x-amz-target", ECR_TARGET)
        .body(payload)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash(bytes: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, bytes).as_ref())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcrResponse {
    authorization_data: Vec<EcrToken>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EcrToken {
    authorization_token: String,
    expires_at: f64,
}

async fn ecr(http: &Client, host: &str) -> Result<Lease> {
    let parts = ECR
        .captures(host)
        .ok_or_else(|| anyhow!("Invalid ECR host."))?;
    let region = &parts[1];
    let endpoint = format!("api.ecr.{region}.{}", &parts[2]);
    let session = aws_session().await?;
    let response: EcrResponse = exchange(
        signed_ecr(http, region, &endpoint, Utc::now(), &session),
        "ECR GetAuthorizationToken (requires ecr:GetAuthorizationToken)",
    )
    .await?;
    ecr_lease(response)
}

fn ecr_lease(response: EcrResponse) -> Result<Lease> {
    // The default registry's token is usable on other registries authorized by
    // this IAM principal in the region. Cross-account pulls use repository IAM.
    let token = response
        .authorization_data
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("ECR returned no registry authorization token."))?;
    let invalid = || anyhow!("ECR returned an invalid registry authorization token.");
    let decoded = STANDARD
        .decode(token.authorization_token)
        .map_err(|_| invalid())?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| invalid())?;
    let password = decoded
        .strip_prefix("AWS:")
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid)?;
    let expiry = DateTime::from_timestamp(token.expires_at as i64, 0).ok_or_else(invalid)?;
    Lease::new(
        Credentials {
            username: "AWS".into(),
            password: password.into(),
        },
        expiry,
    )
}

#[derive(Deserialize)]
struct EntraAccess {
    access_token: String,
    expires_in: i64,
}

#[derive(Deserialize)]
struct AcrRefresh {
    refresh_token: String,
}

async fn acr(http: &Client, host: &str) -> Result<Lease> {
    let id = |key| {
        std::env::var(key)
            .ok()
            .and_then(|value| uuid::Uuid::parse_str(&value).ok())
            .map(|value| value.to_string())
            .ok_or_else(|| anyhow!("Configure {key} for the Certhia Azure workload identity."))
    };
    let tenant = id("AZURE_TENANT_ID")?;
    let client_id = id("AZURE_CLIENT_ID")?;
    let file = std::env::var_os("AZURE_FEDERATED_TOKEN_FILE")
        .ok_or_else(|| anyhow!("Configure the Azure workload identity projected token file."))?;
    let assertion = tokio::fs::read_to_string(file)
        .await
        .map_err(|_| anyhow!("Could not read the Azure workload identity projected token."))?;
    let started = Utc::now();
    let entra: EntraAccess = exchange(
        entra_request(http, &tenant, &client_id, assertion.trim()),
        "Microsoft Entra workload token exchange",
    )
    .await?;
    anyhow::ensure!(
        !entra.access_token.is_empty() && entra.expires_in > 120,
        "Microsoft Entra returned an empty or nearly expired access token."
    );
    let refresh: AcrRefresh = exchange(
        acr_exchange_request(http, host, &tenant, &entra.access_token),
        "ACR refresh token exchange",
    )
    .await?;
    let expiry = jwt_expiry(&refresh.refresh_token)?;
    let entra_expiry = started + chrono::Duration::seconds(entra.expires_in.clamp(0, 86_400));
    Lease::new(
        Credentials {
            username: ACR_USER.into(),
            password: refresh.refresh_token,
        },
        expiry.min(entra_expiry),
    )
}

fn entra_request(
    http: &Client,
    tenant: &str,
    client_id: &str,
    assertion: &str,
) -> reqwest::RequestBuilder {
    http.post(format!(
        "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    ))
    .form(&[
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("scope", "https://containerregistry.azure.net/.default"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion),
    ])
}

fn acr_exchange_request(
    http: &Client,
    host: &str,
    tenant: &str,
    access_token: &str,
) -> reqwest::RequestBuilder {
    http.post(format!("https://{host}/oauth2/exchange")).form(&[
        ("grant_type", "access_token"),
        ("service", host),
        ("tenant", tenant),
        ("access_token", access_token),
    ])
}

// The JWT came directly from the HTTPS registry. Its claims only shorten the
// cache lifetime. ACR verifies the token when clients use it.
fn jwt_expiry(token: &str) -> Result<DateTime<Utc>> {
    #[derive(Deserialize)]
    struct Claims {
        exp: i64,
    }
    let expiry = token
        .split('.')
        .nth(1)
        .and_then(|part| URL_SAFE_NO_PAD.decode(part).ok())
        .and_then(|part| serde_json::from_slice::<Claims>(&part).ok())
        .and_then(|claims| DateTime::from_timestamp(claims.exp, 0));
    expiry.ok_or_else(|| anyhow!("ACR returned a refresh token without a valid expiry."))
}

pub(super) async fn exchange<T: serde::de::DeserializeOwned>(
    request: reqwest::RequestBuilder,
    operation: &str,
) -> Result<T> {
    let response = request
        .send()
        .await
        .map_err(|_| anyhow!("{operation} could not be reached."))?;
    anyhow::ensure!(
        response.status().is_success(),
        "{operation} returned HTTP {}.",
        response.status().as_u16()
    );
    response
        .json()
        .await
        .map_err(|_| anyhow!("{operation} returned an invalid response."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn workload_hosts_and_metadata_endpoints_are_restricted() {
        for host in [
            "123456789012.dkr.ecr.us-gov-west-1.amazonaws.com",
            "123456789012.dkr.ecr.cn-northwest-1.amazonaws.com.cn",
            "testregistry.azurecr.io",
        ] {
            assert!(provider(host).is_ok(), "{host}");
        }
        for host in [
            "public.ecr.aws",
            "testregistry.azurecr.io.example.org",
            "testregistry.azurecr.io:8443",
            "example.org",
        ] {
            assert!(provider(host).is_err(), "{host}");
        }
        assert_eq!(
            aws_metadata_url(Some("/v2/credentials/fixture"), None)
                .unwrap()
                .as_str(),
            "http://169.254.170.2/v2/credentials/fixture"
        );
        assert!(aws_metadata_url(None, Some("http://169.254.170.23/v1/credentials")).is_ok());
        assert!(aws_metadata_url(None, Some("http://[fd00:ec2::23]/v1/credentials")).is_ok());
        assert!(aws_metadata_url(None, Some("http://169.254.170.23@other.example/")).is_err());
        assert!(aws_metadata_url(Some("//other.example"), None).is_err());
    }

    #[test]
    fn ecr_signs_the_regional_api_request_and_session_token() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let at = "2026-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let session = AwsSession {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "secret".into(),
            token: "session".into(),
            expiration: at,
        };
        let request = signed_ecr(
            &client(false).unwrap(),
            "us-east-1",
            "api.ecr.us-east-1.amazonaws.com",
            at,
            &session,
        )
        .build()
        .unwrap();
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.headers()["x-amz-security-token"], "session");
        assert_eq!(
            request.headers()[reqwest::header::AUTHORIZATION],
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/us-east-1/ecr/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=1c4319b81d925fec4b7ce3eedb362b95c46a0a6269e8c6244585e162210c70e9"
        );
    }

    #[test]
    fn acr_uses_the_registry_audience_and_exchanges_the_access_token() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = client(false).unwrap();
        let entra = entra_request(&http, "tenant", "application", "projected+jwt")
            .build()
            .unwrap();
        let acr = acr_exchange_request(&http, "fixture.azurecr.io", "tenant", "entra+jwt")
            .build()
            .unwrap();
        let fields = |request: &reqwest::Request| {
            assert_eq!(request.method(), reqwest::Method::POST);
            assert_eq!(
                request.headers()[reqwest::header::CONTENT_TYPE],
                "application/x-www-form-urlencoded"
            );
            url::form_urlencoded::parse(request.body().unwrap().as_bytes().unwrap())
                .into_owned()
                .collect::<HashMap<_, _>>()
        };
        assert_eq!(
            entra.url().as_str(),
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
        );
        let form = fields(&entra);
        assert_eq!(form["grant_type"], "client_credentials");
        assert_eq!(
            form["scope"],
            "https://containerregistry.azure.net/.default"
        );
        assert_eq!(form["client_assertion"], "projected+jwt");
        assert_eq!(
            acr.url().as_str(),
            "https://fixture.azurecr.io/oauth2/exchange"
        );
        let form = fields(&acr);
        assert_eq!(form["grant_type"], "access_token");
        assert_eq!(form["service"], "fixture.azurecr.io");
        assert_eq!(form["access_token"], "entra+jwt");
    }

    #[test]
    fn tokens_expire_early_and_never_enter_cache_without_an_expiry() {
        let now = Utc::now().timestamp();
        let ecr = |expires_at| {
            serde_json::from_value(json!({
            "authorizationData": [{"authorizationToken": STANDARD.encode("AWS:fixture"), "expiresAt": expires_at}]
        })).unwrap()
        };
        let lease = ecr_lease(ecr(now + 43_200)).unwrap();
        assert_eq!(lease.auth.username, "AWS");
        assert_eq!(lease.auth.password, "fixture");
        assert!(lease.current());
        assert!(lease.refresh_at <= Instant::now() + Duration::from_secs(3600));
        assert!(ecr_lease(ecr(now + 90)).is_err());

        let jwt = |claims: serde_json::Value| {
            format!(
                "header.{}.signature",
                URL_SAFE_NO_PAD.encode(claims.to_string())
            )
        };
        let expiry = jwt_expiry(&jwt(json!({"exp": now}))).unwrap();
        assert!(
            Lease::new(
                Credentials {
                    username: ACR_USER.into(),
                    password: "fixture".into()
                },
                expiry
            )
            .is_err()
        );
        assert!(jwt_expiry(&jwt(json!({}))).is_err());
    }
}
