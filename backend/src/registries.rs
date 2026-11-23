use crate::{
    ApiError, ApiResult, App, ImageReference, credentials, registry_host, scanner::Credentials,
};
use anyhow::{Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get as route_get,
};
use regex::Regex;
use reqwest::{Client, Response, header::WWW_AUTHENTICATE};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{sync::LazyLock, time::Duration};
use url::Url;

mod cloud;

pub const PROVIDERS: &[&str] = &[
    "oci",
    "dockerhub",
    "ghcr",
    "gitlab",
    "gar",
    "ecr",
    "acr",
    "harbor",
    "nexus",
    "artifactory",
    "gitea",
    "forgejo",
    "quay",
];
static PARAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"([a-zA-Z_]+)="([^"]*)""#).unwrap());

pub fn routes() -> Router<App> {
    Router::new()
        .route("/registries/{id}/catalog", route_get(catalog).post(refresh))
        .route("/registries/{id}/tags", route_get(tags))
        .route("/registries/{id}/test", axum::routing::post(test_saved))
        .route("/registries/{id}", axum::routing::put(update))
        .route("/discover/dockerhub", route_get(dockerhub))
        .route("/discover/dockerhub/tags", route_get(dockerhub_tags))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    #[serde(default)]
    pub provider: Option<String>,
    pub auth_host: Option<String>,
    #[serde(default)]
    pub auto_sync: bool,
    pub protocol: Option<String>,
    pub namespace: Option<String>,
    #[serde(default)]
    pub skip_tls: bool,
}

impl Options {
    pub fn validate(self) -> ApiResult<Self> {
        if self
            .provider
            .as_deref()
            .is_some_and(|value| !PROVIDERS.contains(&value))
        {
            return Err(ApiError::bad("Select a supported registry provider."));
        }
        if self
            .protocol
            .as_deref()
            .is_some_and(|value| !matches!(value, "https" | "http"))
        {
            return Err(ApiError::bad("Select HTTP or HTTPS."));
        }
        let auth_host = self
            .auth_host
            .filter(|value| !value.trim().is_empty())
            .map(|value| registry_host(&value))
            .transpose()
            .map_err(ApiError::bad)?;
        let namespace = self
            .namespace
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        if namespace.as_ref().is_some_and(|value| {
            value.len() > 170
                || value.split('/').any(|part| {
                    part.is_empty()
                        || part == "."
                        || part == ".."
                        || !part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                        })
                })
        }) {
            return Err(ApiError::bad(
                "Enter a valid registry namespace or project/repository.",
            ));
        }
        Ok(Self {
            auth_host,
            namespace,
            ..self
        })
    }
}

fn workload(auth: Option<&Credentials>) -> bool {
    auth.is_some_and(|auth| auth.username == cloud::MARKER && auth.password == cloud::MARKER)
}

fn validate_workload(
    app: &App,
    host: &str,
    secret: Option<&[u8]>,
    options: &Options,
) -> ApiResult<()> {
    if let Some(secret) = secret
        && workload(Some(&app.0.vault.open_secret(host, secret)?))
    {
        let provider = cloud::provider(host).map_err(ApiError::bad)?;
        if options.provider.as_deref() != Some(provider.name())
            || options.protocol.as_deref().unwrap_or("https") != "https"
            || options.skip_tls
            || options.auth_host.is_some()
        {
            return Err(ApiError::bad(
                "Workload identity requires the matching provider and verified HTTPS on the registry host.",
            ));
        }
    }
    Ok(())
}

pub async fn add(
    app: &App,
    name: &str,
    host: &str,
    secret: Option<Vec<u8>>,
    options: Options,
) -> ApiResult<crate::store::Registry> {
    validate_workload(app, host, secret.as_deref(), &options)?;
    let id = uuid::Uuid::now_v7();
    let mut tx = app.0.database.primary.begin().await?;
    let registry = sqlx::query_scalar!(
        "INSERT INTO registries(id,name,host) VALUES($1,$2,$2)
        ON CONFLICT(host) DO UPDATE SET host=excluded.host RETURNING id",
        uuid::Uuid::now_v7(),
        host
    )
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query!(
        "INSERT INTO registry_profiles(id,registry_id,name,secret) VALUES($1,$2,$3,$4)",
        id,
        registry,
        name,
        secret
    )
    .execute(&mut *tx)
    .await?;
    let provider = options.provider.as_deref().unwrap_or("oci");
    let protocol = options.protocol.as_deref().unwrap_or("https");
    sqlx::query!("INSERT INTO registry_config(registry_id,provider,auth_host,auto_sync,protocol,skip_tls,namespace)
                 VALUES($1,$2,$3,$4,$5,$6,$7)",id,provider,options.auth_host,options.auto_sync,protocol,options.skip_tls,options.namespace)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    let id = id.to_string();
    Ok(crate::store::Registry {
        id,
        name: name.into(),
        host: host.into(),
        authenticated: secret.is_some(),
        provider: provider.into(),
        auth_host: options.auth_host,
        auto_sync: options.auto_sync,
        protocol: protocol.into(),
        skip_tls: options.skip_tls,
        namespace: options.namespace,
    })
}

#[derive(Deserialize)]
struct Update {
    name: String,
    username: Option<String>,
    password: Option<String>,
    #[serde(default)]
    clear_credentials: bool,
    #[serde(flatten)]
    options: Options,
}

async fn update(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<Update>,
) -> ApiResult<StatusCode> {
    let key = uuid::Uuid::parse_str(&id).map_err(|_| ApiError::missing("Registry not found."))?;
    let mut tx = app.0.database.primary.begin().await?;
    let saved = sqlx::query!(
        "SELECT r.host,p.secret FROM registry_profiles p JOIN registries r ON p.registry_id=r.id
                            WHERE p.id=$1 FOR UPDATE OF p",
        key
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::missing("Registry not found."))?;
    let (host, old) = (saved.host, saved.secret);
    let name = input.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::bad(
            "Enter a registry name of up to 100 characters.",
        ));
    }
    let options = input.options.validate()?;
    let secret = if input.clear_credentials {
        None
    } else if input
        .username
        .as_ref()
        .is_some_and(|value| !value.is_empty())
        || input
            .password
            .as_ref()
            .is_some_and(|value| !value.is_empty())
    {
        credentials(
            input.username.unwrap_or_default(),
            input.password.unwrap_or_default(),
        )?
        .map(|auth| app.0.vault.seal(&host, &auth))
        .transpose()?
    } else {
        old
    };
    validate_workload(&app, &host, secret.as_deref(), &options)?;
    sqlx::query!(
        "UPDATE registry_profiles SET name=$2,secret=$3 WHERE id=$1",
        key,
        name,
        secret
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!("UPDATE registry_config SET provider=$2,auth_host=$3,auto_sync=$4,protocol=$5,skip_tls=$6,namespace=$7
        WHERE registry_id=$1",key,options.provider.as_deref().unwrap_or("oci"),options.auth_host,options.auto_sync,options.protocol.as_deref().unwrap_or("https"),options.skip_tls,options.namespace)
        .execute(&mut *tx).await?;
    sqlx::query!("DELETE FROM registry_catalog WHERE registry_id=$1", key)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    app.0.database.audit("registry.updated", &id, &host).await?;
    Ok(StatusCode::NO_CONTENT)
}

struct Connection {
    host: String,
    auth_host: Option<String>,
    auth: Option<Credentials>,
    protocol: String,
    skip_tls: bool,
    provider: String,
    namespace: Option<String>,
}

async fn connection(app: &App, id: &str) -> ApiResult<Connection> {
    let id = uuid::Uuid::parse_str(id).map_err(|_| ApiError::missing("Registry not found."))?;
    let row = sqlx::query!(
        "SELECT host,p.secret,provider,auth_host,protocol,skip_tls,namespace
        FROM registry_profiles p JOIN registries r ON r.id=p.registry_id
        JOIN registry_config c ON c.registry_id=p.id WHERE p.id=$1",
        id
    )
    .fetch_optional(&app.0.database.primary)
    .await?
    .ok_or_else(|| ApiError::missing("Registry not found."))?;
    Ok(Connection {
        auth: row
            .secret
            .map(|s| app.0.vault.open_secret(&row.host, &s))
            .transpose()?,
        host: row.host,
        auth_host: row.auth_host,
        protocol: row.protocol,
        skip_tls: row.skip_tls,
        provider: row.provider,
        namespace: row.namespace,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestTarget {
    reference: String,
    platform: Option<String>,
    protocol: Option<String>,
    skip_tls: Option<bool>,
}

async fn test_saved(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<TestTarget>,
) -> ApiResult<Json<Value>> {
    let mut connection = connection(&app, &id).await?;
    let reference =
        ImageReference::parse(&input.reference, Some(&connection.host)).map_err(ApiError::bad)?;
    let platform = input.platform.as_deref().unwrap_or(crate::domain::PLATFORMS[0]);
    crate::validate_platform(platform)?;
    if let Some(protocol) = input.protocol {
        if !matches!(protocol.as_str(), "https" | "http") {
            return Err(ApiError::bad("Choose HTTPS or HTTP for the registry."));
        }
        connection.protocol = protocol;
    }
    if let Some(skip_tls) = input.skip_tls {
        connection.skip_tls = skip_tls;
    }
    if matches!(
        connection.provider.as_str(),
        "ghcr" | "forgejo" | "ecr" | "acr"
    ) {
        manifest(&connection, &reference)
            .await
            .map_err(ApiError::bad)?;
    }
    // Keep workload identity refresh on the same path used by image pulls.
    let insecure = connection.protocol == "http" || connection.skip_tls;
    let credentials = if workload(connection.auth.as_ref()) {
        Some(cloud::scanner_marker().map_err(ApiError::bad)?)
    } else {
        connection.auth
    };
    crate::images::verify_access(&reference, platform, credentials, insecure)
        .await
        .map_err(ApiError::bad)?;
    Ok(Json(json!({"reference":reference.value,"platform":platform})))
}

pub async fn insecure(app: &App, id: Option<&str>) -> Result<bool> {
    let Some(id) = id else { return Ok(false) };
    let id = uuid::Uuid::parse_str(id)?;
    Ok(sqlx::query_scalar!(r#"SELECT (protocol='http' OR skip_tls) AS "insecure!" FROM registry_config WHERE registry_id=$1"#,id)
        .fetch_optional(&app.0.database.primary).await?.unwrap_or(false))
}

fn client(insecure: bool) -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .tls_danger_accept_invalid_certs(insecure)
        .user_agent(crate::PRODUCT_NAME)
        .build()?)
}

fn allowed_realm(base: &str, protocol: &str, realm: &Url, explicit: Option<&str>) -> bool {
    let Some(host) = realm.host_str() else {
        return false;
    };
    if (realm.scheme() != "https" && !(realm.scheme() == "http" && protocol == "http"))
        || !realm.username().is_empty()
        || realm.password().is_some()
    {
        return false;
    }
    if explicit.is_some_and(|other| {
        registry_host(&realm[..url::Position::BeforePath])
            .ok()
            .as_deref()
            == Some(other)
    }) {
        return true;
    }
    let Some(registry) = Url::parse(&format!("https://{base}")).ok() else {
        return false;
    };
    let Some(registry_host) = registry.host_str() else {
        return false;
    };
    host == registry_host
        || host
            .strip_suffix(registry_host)
            .is_some_and(|prefix| prefix.ends_with('.'))
        || registry_host
            .strip_suffix(host)
            .is_some_and(|prefix| prefix.ends_with('.') && host.contains('.'))
}

#[derive(Clone, Copy)]
enum OciOperation {
    Catalog,
    Tags,
    Manifest,
}

impl OciOperation {
    fn failed(self, status: reqwest::StatusCode, token_exchange: bool) -> anyhow::Error {
        let hint = match self {
            Self::Catalog => {
                "Check catalog-list permission. You can still test a known image by tag or digest."
            }
            Self::Tags => {
                "Check access to list tags for this repository. Try an exact tag or digest if you know one."
            }
            Self::Manifest => {
                "Check the exact repository, tag or digest and the credential’s pull permission."
            }
        };
        let operation = match self {
            Self::Catalog => "OCI catalog listing",
            Self::Tags => "OCI tag listing",
            Self::Manifest => "Exact image manifest lookup",
        };
        let phase = if token_exchange {
            " token exchange"
        } else {
            ""
        };
        anyhow!(
            "{operation}{phase} returned HTTP {}. {hint}",
            status.as_u16()
        )
    }
}

const MANIFEST_TYPES: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";

async fn manifest(connection: &Connection, reference: &ImageReference) -> Result<()> {
    let (_, exact) = reference.value.split_once('/').unwrap();
    let (repository, target) = exact
        .rsplit_once('@')
        .or_else(|| exact.rsplit_once(':'))
        .unwrap();
    let response = get(
        connection,
        &format!("/v2/{repository}/manifests/{target}"),
        &[],
        OciOperation::Manifest,
    )
    .await?;
    let payload: Value = response
        .json()
        .await
        .map_err(|_| anyhow!("The registry did not return an image manifest."))?;
    anyhow::ensure!(
        payload["schemaVersion"] == 2,
        "The registry did not return a supported image manifest."
    );
    Ok(())
}

async fn get(
    connection: &Connection,
    path: &str,
    query: &[(&str, &str)],
    operation: OciOperation,
) -> Result<Response> {
    let managed = workload(connection.auth.as_ref());
    if managed {
        anyhow::ensure!(
            connection.protocol == "https" && !connection.skip_tls,
            "Workload identity requires verified HTTPS."
        );
    }
    let client = client(connection.skip_tls)?;
    let host = if connection.host == "docker.io" {
        "registry-1.docker.io"
    } else {
        &connection.host
    };
    let endpoint = format!("{}://{host}{path}", connection.protocol);
    let request = || {
        let request = client.get(&endpoint).query(query);
        if matches!(operation, OciOperation::Manifest) {
            request.header(reqwest::header::ACCEPT, MANIFEST_TYPES)
        } else {
            request
        }
    };
    let send_error = |_| anyhow!("Could not contact the registry.");
    let check = |response: Response, token_exchange| {
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(operation.failed(response.status(), token_exchange))
        }
    };
    let response = request().send().await.map_err(send_error)?;
    if response.status() != reqwest::StatusCode::UNAUTHORIZED {
        return check(response, false);
    }
    let challenge = response
        .headers()
        .get_all(WWW_AUTHENTICATE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|challenge| {
            challenge
                .get(..7)
                .is_some_and(|value| value.eq_ignore_ascii_case("bearer "))
        });
    if let Some(challenge) = challenge {
        let parameters: std::collections::HashMap<_, _> = PARAM
            .captures_iter(challenge)
            .map(|capture| {
                (
                    capture.get(1).unwrap().as_str(),
                    capture.get(2).unwrap().as_str(),
                )
            })
            .collect();
        let realm = Url::parse(parameters.get("realm").copied().unwrap_or_default())
            .map_err(|_| anyhow!("The registry sent an invalid authentication challenge."))?;
        let allowed = if managed {
            realm.scheme() == "https"
                && realm.host_str() == Some(host)
                && realm.port().is_none()
                && realm.username().is_empty()
                && realm.password().is_none()
        } else {
            allowed_realm(
                &connection.host,
                &connection.protocol,
                &realm,
                connection.auth_host.as_deref(),
            )
        };
        anyhow::ensure!(
            allowed,
            "The registry sent an untrusted token host. Check the connection’s token host setting."
        );
        let auth = connection_credentials(connection).await?;
        let mut token_request = client.get(realm.clone());
        for key in ["service", "scope"] {
            if let Some(value) = parameters.get(key) {
                token_request = token_request.query(&[(key, *value)]);
            }
        }
        if let Some(auth) = &auth {
            token_request = if connection.provider == "acr" && auth.username == cloud::ACR_USER {
                let service = parameters.get("service").copied().unwrap_or(host);
                anyhow::ensure!(
                    realm.path() == "/oauth2/token"
                        && service == host
                        && realm.scheme() == "https"
                        && realm.host_str() == Some(host)
                        && realm.port().is_none()
                        && !connection.skip_tls,
                    "ACR returned an unexpected token endpoint."
                );
                client.post(realm).form(&[
                    ("grant_type", "refresh_token"),
                    ("service", service),
                    (
                        "scope",
                        parameters.get("scope").copied().unwrap_or_default(),
                    ),
                    ("refresh_token", auth.password.as_str()),
                ])
            } else {
                token_request.basic_auth(&auth.username, Some(&auth.password))
            };
        }
        let token: Value = check(
            token_request
                .send()
                .await
                .map_err(|_| anyhow!("Registry token exchange failed."))?,
            true,
        )?
        .json()
        .await
        .map_err(|_| anyhow!("The registry did not return a token."))?;
        let token = token["token"]
            .as_str()
            .or_else(|| token["access_token"].as_str())
            .ok_or_else(|| anyhow!("The registry did not return a token."))?;
        check(
            request()
                .bearer_auth(token)
                .send()
                .await
                .map_err(send_error)?,
            false,
        )
    } else if let Some(auth) = connection_credentials(connection).await? {
        check(
            request()
                .basic_auth(&auth.username, Some(&auth.password))
                .send()
                .await
                .map_err(send_error)?,
            false,
        )
    } else {
        check(response, false)
    }
}

fn checked(response: Response) -> Result<Response> {
    if !response.status().is_success() {
        bail!(
            "Registry returned HTTP {}. You can scan an exact image reference even when the catalog is unavailable.",
            response.status().as_u16()
        );
    }
    Ok(response)
}

async fn fetch_catalog(app: &App, id: &str) -> ApiResult<()> {
    let connection = connection(app, id).await?;
    let result: Result<Vec<String>> = async {
        if let Some(items) = provider_catalog(&connection).await? {
            return Ok(items);
        }
        let mut images = Vec::new();
        let mut last = String::new();
        loop {
            let query = if last.is_empty() {
                vec![("n", "100")]
            } else {
                vec![("n", "100"), ("last", &last)]
            };
            let response = get(&connection, "/v2/_catalog", &query, OciOperation::Catalog).await?;
            let more = response.headers().contains_key(reqwest::header::LINK);
            let data: Value = response
                .json()
                .await
                .map_err(|_| anyhow!("The registry returned an invalid catalog."))?;
            let page = data["repositories"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if page.is_empty() {
                break;
            }
            let next = page.last().unwrap().clone();
            images.extend(page);
            if !more {
                break;
            }
            anyhow::ensure!(next > last, "Registry returned a non-advancing page");
            last = next;
        }
        images.sort();
        images.dedup();
        Ok(images)
    }
    .await;
    let key = uuid::Uuid::parse_str(id).map_err(ApiError::bad)?;
    let timestamp = chrono::Utc::now();
    let mut tx = app.0.database.primary.begin().await?;
    let error = result.as_ref().err().map(ToString::to_string);
    sqlx::query!("INSERT INTO registry_catalog(registry_id,refreshed_at,error) VALUES($1,$2,$3)
        ON CONFLICT(registry_id) DO UPDATE SET refreshed_at=excluded.refreshed_at,error=excluded.error",
        key,timestamp,error).execute(&mut *tx).await?;
    if let Ok(images) = result {
        sqlx::query!(
            "DELETE FROM registry_catalog_entries WHERE registry_id=$1",
            key
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!("INSERT INTO registry_catalog_entries(registry_id,repository,tag) SELECT DISTINCT $1::uuid,n,'' FROM unnest($2::text[]) AS n",
            key,&images).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn cached(app: &App, id: &str, page: Page) -> ApiResult<Json<Value>> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let id = uuid::Uuid::parse_str(id).map_err(ApiError::bad)?;
    let limit = page.limit.unwrap_or(100);
    if !(1..=250).contains(&limit) {
        return Err(ApiError::bad("Choose a page size between 1 and 250."));
    }
    let search = page.search.unwrap_or_default();
    let after = if let Some(cursor) = page.cursor {
        let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(ApiError::bad)?;
        let (profile, filter, after): (String, String, String) =
            serde_json::from_slice(&bytes).map_err(ApiError::bad)?;
        if profile != id.to_string() || filter != search {
            return Err(ApiError::bad("Cursor does not match catalog search."));
        }
        after
    } else {
        String::new()
    };
    let row = sqlx::query!(
        "SELECT refreshed_at,error FROM registry_catalog WHERE registry_id=$1",
        id
    )
    .fetch_optional(&app.0.database.primary)
    .await?;
    let mut images = sqlx::query_scalar!(
        "SELECT repository FROM registry_catalog_entries WHERE registry_id=$1
        AND repository>$2 AND strpos(lower(repository),lower($3))>0 ORDER BY repository LIMIT $4",
        id,
        after,
        search,
        limit + 1
    )
    .fetch_all(&app.0.database.primary)
    .await?;
    let cursor = if images.len() > limit as usize {
        images.pop();
        Some(
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&(id.to_string(), search, images.last()))
                    .map_err(anyhow::Error::from)?,
            ),
        )
    } else {
        None
    };
    let (refreshed, error) = row.map(|r| (r.refreshed_at, r.error)).unwrap_or_default();
    Ok(Json(
        json!({"images":images,"refreshedAt":refreshed,"error":error,"nextCursor":cursor}),
    ))
}

async fn catalog(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(page): Query<Page>,
) -> ApiResult<Json<Value>> {
    cached(&app, &id, page).await
}

async fn refresh(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(page): Query<Page>,
) -> ApiResult<Json<Value>> {
    fetch_catalog(&app, &id).await?;
    app.0
        .database
        .audit("registry.catalog.synced", &id, "")
        .await?;
    cached(&app, &id, page).await
}

#[derive(Deserialize)]
struct Tags {
    image: String,
}

async fn tags(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<Tags>,
) -> ApiResult<Json<Value>> {
    let connection = connection(&app, &id).await?;
    let reference =
        ImageReference::parse(&query.image, Some(&connection.host)).map_err(ApiError::bad)?;
    let full = crate::operations::repository(&reference.value);
    let (_, image) = full
        .split_once('/')
        .ok_or_else(|| ApiError::bad("Enter a repository path."))?;
    let result = get(
        &connection,
        &format!("/v2/{image}/tags/list"),
        &[("n", "1000")],
        OciOperation::Tags,
    )
    .await;
    let response = match result {
        Ok(response) => response,
        Err(_) if connection.provider == "nexus" && connection.namespace.is_some() => {
            let entries = nexus_entries(
                &connection,
                &client(connection.skip_tls)?,
                connection.namespace.as_deref().unwrap(),
            )
            .await
            .map_err(ApiError::bad)?;
            let tags: std::collections::BTreeSet<_> = entries
                .iter()
                .filter(|entry| entry["name"] == image)
                .filter_map(|entry| entry["version"].as_str())
                .collect();
            return Ok(Json(json!({"tags":tags})));
        }
        Err(error) => return Err(ApiError::bad(error)),
    };
    let data: Value = response
        .json()
        .await
        .map_err(|_| ApiError::bad("The registry returned invalid tags."))?;
    Ok(Json(
        json!({"tags":data["tags"].as_array().cloned().unwrap_or_default()}),
    ))
}

async fn dockerhub_tags(Query(query): Query<Tags>) -> ApiResult<Json<Value>> {
    let reference =
        ImageReference::parse(&query.image, Some("docker.io")).map_err(ApiError::bad)?;
    let image = crate::operations::repository(&reference.value)
        .strip_prefix("docker.io/")
        .expect("canonical Docker Hub reference");
    let connection = Connection {
        host: "docker.io".into(),
        auth_host: None,
        auth: None,
        protocol: "https".into(),
        skip_tls: false,
        provider: "dockerhub".into(),
        namespace: None,
    };
    let response = get(
        &connection,
        &format!("/v2/{image}/tags/list"),
        &[("n", "1000")],
        OciOperation::Tags,
    )
    .await
    .map_err(ApiError::bad)?;
    let data: Value = response
        .json()
        .await
        .map_err(|_| ApiError::bad("Docker Hub returned invalid tags."))?;
    Ok(Json(
        json!({"tags":data["tags"].as_array().cloned().unwrap_or_default()}),
    ))
}

#[derive(Deserialize)]
struct Search {
    q: String,
}

async fn dockerhub(Query(search): Query<Search>) -> ApiResult<Json<Value>> {
    let query = search.q.trim();
    if query.len() < 2 || query.len() > 100 {
        return Err(ApiError::bad("Enter between 2 and 100 characters."));
    }
    let response = client(false)?
        .get("https://hub.docker.com/v2/search/repositories/")
        .query(&[("query", query), ("page_size", "15")])
        .send()
        .await
        .map_err(|_| ApiError::bad("Docker Hub search is unavailable."))?;
    let payload: Value = checked(response)
        .map_err(ApiError::bad)?
        .json()
        .await
        .map_err(|_| ApiError::bad("Docker Hub returned an invalid response."))?;
    let entries = payload["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let name = entry["repo_name"]
                .as_str()
                .or_else(|| entry["name"].as_str())?;
            let ref_name = if name.contains('/') {
                name.to_owned()
            } else {
                format!("library/{name}")
            };
            Some(json!({"reference":format!("docker.io/{ref_name}:latest"),"label":name}))
        })
        .collect::<Vec<_>>();
    Ok(Json(json!(entries)))
}

async fn auto_items(app: &App) -> Result<Vec<String>> {
    let ids=sqlx::query_scalar!("SELECT rc.registry_id FROM registry_config rc LEFT JOIN registry_catalog c USING(registry_id)
        WHERE rc.auto_sync AND (c.refreshed_at IS NULL OR c.refreshed_at < now()-interval '15 minutes')
        ORDER BY c.refreshed_at NULLS FIRST,rc.registry_id LIMIT 5").fetch_all(&app.0.database.primary).await?;
    Ok(ids.into_iter().map(|id| id.to_string()).collect())
}

pub async fn sync(app: App) {
    let mut ticks = tokio::time::interval(Duration::from_secs(60));
    loop {
        ticks.tick().await;
        if let Ok(entries) = auto_items(&app).await {
            for id in entries {
                let _ = fetch_catalog(&app, &id).await;
            }
        }
    }
}

async fn provider_catalog(connection: &Connection) -> Result<Option<Vec<String>>> {
    let Some(namespace) = connection.namespace.as_deref() else {
        if matches!(connection.provider.as_str(), "ghcr" | "forgejo") {
            bail!(
                "Set the package owner namespace to browse this registry’s catalog. You can look up tags or test a known image by tag or digest."
            );
        }
        return Ok(None);
    };
    let http = client(
        connection.skip_tls
            && matches!(connection.provider.as_str(), "gitea" | "forgejo" | "nexus"),
    )?;
    let images: Vec<String> = match connection.provider.as_str() {
        "dockerhub" if connection.host == "docker.io" => {
            let mut request = http
                .get(format!(
                    "https://hub.docker.com/v2/namespaces/{namespace}/repositories"
                ))
                .query(&[("page_size", "100")]);
            if let Some(auth) = &connection.auth {
                let data: Value = checked(
                    http.post("https://hub.docker.com/v2/auth/token")
                        .json(&json!({"identifier":auth.username,"secret":auth.password}))
                        .send()
                        .await?,
                )?
                .json()
                .await?;
                let token = data["access_token"]
                    .as_str()
                    .ok_or_else(|| anyhow!("Docker Hub returned no access token."))?;
                request = request.bearer_auth(token);
            }
            let payload: Value = checked(request.send().await?)?.json().await?;
            payload["results"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|entry| entry["name"].as_str())
                .map(|name| format!("{namespace}/{name}"))
                .collect()
        }
        "ghcr" if connection.host == "ghcr.io" => {
            github_catalog(connection, &http, "https://api.github.com", namespace).await?
        }
        "gitlab" if connection.host == "registry.gitlab.com" || connection.auth_host.is_some() => {
            let auth = connection
                .auth
                .as_ref()
                .ok_or_else(|| anyhow!("Add a GitLab token with registry and API access."))?;
            let api_host = if connection.host == "registry.gitlab.com" {
                "gitlab.com"
            } else {
                connection.auth_host.as_deref().unwrap()
            };
            let mut uri = Url::parse(&format!("https://{api_host}/api/v4/groups"))?;
            uri.path_segments_mut()
                .map_err(|_| anyhow!("Invalid GitLab API host."))?
                .extend([namespace, "registry", "repositories"]);
            let results: Vec<Value> = checked(
                http.get(uri)
                    .query(&[("per_page", "100")])
                    .header("PRIVATE-TOKEN", &auth.password)
                    .send()
                    .await?,
            )?
            .json()
            .await?;
            results
                .iter()
                .filter_map(|entry| entry["path"].as_str())
                .map(str::to_owned)
                .collect()
        }
        "gitea" | "forgejo" => {
            let host = connection.auth_host.as_deref().unwrap_or(&connection.host);
            let mut url = Url::parse(&format!("{}://{host}/api/v1/packages", connection.protocol))?;
            url.path_segments_mut()
                .map_err(|_| anyhow!("Invalid Gitea API host."))?
                .push(namespace);
            let owner = namespace.to_ascii_lowercase();
            let mut packages = Vec::new();
            for page in 1..=10 {
                let mut request = http.get(url.clone()).query(&[
                    ("type", "container"),
                    ("limit", "100"),
                    ("page", &page.to_string()),
                ]);
                if let Some(auth) = &connection.auth {
                    request = request.header(
                        reqwest::header::AUTHORIZATION,
                        format!("token {}", auth.password),
                    );
                }
                let response = request
                    .send()
                    .await
                    .map_err(|_| anyhow!("Could not contact the package catalog API."))?;
                anyhow::ensure!(
                    response.status().is_success(),
                    "{} package catalog returned HTTP {}. Check the namespace, package visibility, and the access token’s read:package scope.",
                    if connection.provider == "forgejo" {
                        "Forgejo"
                    } else {
                        "Gitea"
                    },
                    response.status().as_u16()
                );
                let entries: Vec<Value> = response
                    .json()
                    .await
                    .map_err(|_| anyhow!("The package catalog API returned invalid packages."))?;
                if entries.is_empty() {
                    break;
                }
                packages.extend(
                    entries
                        .iter()
                        .filter_map(|item| item["name"].as_str())
                        .map(|name| format!("{owner}/{name}")),
                );
            }
            packages
        }
        "nexus" => nexus_entries(connection, &http, namespace)
            .await?
            .into_iter()
            .filter_map(|item| item["name"].as_str().map(str::to_owned))
            .collect(),
        "gar" if connection.host.ends_with("-docker.pkg.dev") => {
            let (project, repository) = namespace
                .split_once('/')
                .ok_or_else(|| anyhow!("Enter the Artifact Registry project/repository."))?;
            let location = connection.host.trim_end_matches("-docker.pkg.dev");
            let auth = connection
                .auth
                .as_ref()
                .ok_or_else(|| anyhow!("Add an Artifact Registry token or service account key."))?;
            let token = google_token(&http, auth).await?;
            let url = format!(
                "https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{location}/repositories/{repository}/dockerImages"
            );
            let payload: Value = checked(
                http.get(url)
                    .query(&[("pageSize", "1000")])
                    .bearer_auth(token)
                    .send()
                    .await?,
            )?
            .json()
            .await?;
            payload["dockerImages"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|entry| entry["uri"].as_str())
                .filter_map(|uri| uri.strip_prefix(&format!("{}/", connection.host)))
                .map(|uri| crate::operations::repository(uri).to_owned())
                .collect()
        }
        _ => return Ok(None),
    };
    let images = std::collections::BTreeSet::from_iter(images)
        .into_iter()
        .collect();
    Ok(Some(images))
}

async fn github_catalog(
    connection: &Connection,
    http: &Client,
    origin: &str,
    namespace: &str,
) -> Result<Vec<String>> {
    let auth = connection.auth.as_ref().ok_or_else(|| anyhow!(
        "GitHub package catalog requires a classic personal access token with read:packages. You can look up public image tags or test a known public image anonymously."
    ))?;
    let owner = namespace.to_ascii_lowercase();
    let mut images = Vec::new();
    let mut kind = "orgs";
    for page in 1..=100 {
        let fetch = |kind| {
            http.get(format!("{origin}/{kind}/{namespace}/packages"))
                .query(&[
                    ("package_type", "container"),
                    ("per_page", "100"),
                    ("page", &page.to_string()),
                ])
                .header("Accept", "application/vnd.github+json")
                .bearer_auth(&auth.password)
                .send()
        };
        let unavailable = |_| anyhow!("Could not contact the GitHub package catalog API.");
        let mut response = fetch(kind).await.map_err(unavailable)?;
        if page == 1 && response.status() == reqwest::StatusCode::NOT_FOUND {
            kind = "users";
            response = fetch(kind).await.map_err(unavailable)?;
        }
        anyhow::ensure!(
            response.status().is_success(),
            "GitHub package catalog returned HTTP {}. Check the owner namespace, classic token read:packages scope, organization SSO authorization, and package access. You can still look up OCI tags or test an exact image separately.",
            response.status().as_u16()
        );
        let entries: Vec<Value> = response
            .json()
            .await
            .map_err(|_| anyhow!("GitHub returned an invalid package catalog."))?;
        images.extend(
            entries
                .iter()
                .filter_map(|entry| entry["name"].as_str())
                .map(|name| format!("{owner}/{name}")),
        );
        if entries.len() < 100 {
            return Ok(images);
        }
    }
    bail!("The GitHub package catalog exceeded the supported page limit.")
}

async fn nexus_entries(
    connection: &Connection,
    http: &Client,
    repository: &str,
) -> Result<Vec<Value>> {
    let host = connection.auth_host.as_deref().unwrap_or(&connection.host);
    let url = format!(
        "{}://{host}/service/rest/v1/components",
        connection.protocol
    );
    let mut cursor = None::<String>;
    let mut entries = Vec::new();
    for _ in 0..10 {
        let mut request = http.get(&url).query(&[("repository", repository)]);
        if let Some(value) = cursor.as_deref() {
            request = request.query(&[("continuationToken", value)]);
        }
        if let Some(auth) = &connection.auth {
            request = request.basic_auth(&auth.username, Some(&auth.password));
        }
        let value: Value = checked(request.send().await?)?.json().await?;
        entries.extend(
            value["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|item| item["format"] == "docker")
                .cloned(),
        );
        let next = value["continuationToken"].as_str().map(str::to_owned);
        if next.is_none() || cursor == next {
            break;
        }
        cursor = next;
    }
    Ok(entries)
}

async fn connection_credentials(connection: &Connection) -> Result<Option<Credentials>> {
    if workload(connection.auth.as_ref()) {
        return cloud::resolve(&connection.host).await.map(Some);
    }
    pull_credentials(&connection.host, connection.auth.clone()).await
}

pub async fn pull_credentials(
    host: &str,
    credentials: Option<Credentials>,
) -> Result<Option<Credentials>> {
    if let Some(auth) = &credentials
        && auth.username == cloud::MARKER
    {
        anyhow::ensure!(
            cloud::is_scanner_marker(auth),
            "Save a verified HTTPS registry connection before using server workload identity."
        );
        return cloud::resolve(host).await.map(Some);
    }
    if let Some(auth) = &credentials
        && host.ends_with("-docker.pkg.dev")
        && matches!(auth.username.as_str(), "_json_key" | "_json_key_base64")
    {
        return Ok(Some(Credentials {
            username: "oauth2accesstoken".into(),
            password: google_token(&client(false)?, auth).await?,
        }));
    }
    Ok(credentials)
}

async fn google_token(http: &Client, auth: &Credentials) -> Result<String> {
    use base64::{
        Engine,
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    };
    use ring::{
        rand::SystemRandom,
        signature::{RSA_PKCS1_SHA256, RsaKeyPair},
    };
    if auth.username == "oauth2accesstoken" || auth.username == "_dcgcloud_token" {
        return Ok(auth.password.clone());
    }
    let decoded = if auth.username == "_json_key_base64" {
        STANDARD.decode(auth.password.trim())?
    } else {
        auth.password.as_bytes().to_vec()
    };
    let account: Value = serde_json::from_slice(&decoded)
        .map_err(|_| anyhow!("Enter a service account JSON key or an OAuth access token."))?;
    let email = account["client_email"]
        .as_str()
        .ok_or_else(|| anyhow!("Service account key has no client email."))?;
    let pem = account["private_key"]
        .as_str()
        .ok_or_else(|| anyhow!("Service account key has no private key."))?;
    let der = STANDARD.decode(
        pem.lines()
            .filter(|line| !line.starts_with('-'))
            .collect::<String>(),
    )?;
    let key =
        RsaKeyPair::from_pkcs8(&der).map_err(|_| anyhow!("Invalid service account RSA key."))?;
    let now = chrono::Utc::now().timestamp();
    let endpoint = "https://oauth2.googleapis.com/token";
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
        &json!({"iss":email,"scope":"https://www.googleapis.com/auth/cloud-platform",
        "aud":endpoint,"iat":now,"exp":now+3600}),
    )?);
    let signed = format!("{header}.{body}");
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        signed.as_bytes(),
        &mut signature,
    )
    .map_err(|_| anyhow!("Could not sign the service account token."))?;
    let assertion = format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature));
    let response: Value = checked(
        http.post(endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await?,
    )?
    .json()
    .await?;
    Ok(response["access_token"]
        .as_str()
        .ok_or_else(|| anyhow!("Google OAuth returned no access token."))?
        .to_owned())
}

pub async fn credential_record(app: &App, id: &str) -> Result<Option<(String, Option<Vec<u8>>)>> {
    let Ok(id) = uuid::Uuid::parse_str(id) else {
        return Ok(None);
    };
    Ok(sqlx::query!("SELECT r.host,p.secret FROM registry_profiles p JOIN registries r ON p.registry_id=r.id WHERE p.id=$1",id)
        .fetch_optional(&app.0.database.primary).await?
        .map(|row| -> Result<_> {
            let mut secret = row.secret;
            if cloud::provider(&row.host).is_ok()
                && let Some(value) = &secret
                && workload(Some(&app.0.vault.open_secret(&row.host, value)?))
            {
                secret = Some(app.0.vault.seal(&row.host, &cloud::scanner_marker()?)?);
            }
            Ok((row.host, secret))
        })
        .transpose()?)
}

#[derive(Deserialize, Default)]
pub struct Page {
    cursor: Option<String>,
    limit: Option<i64>,
    search: Option<String>,
}

pub async fn list(
    State(app): State<App>,
    Query(page): Query<Page>,
) -> ApiResult<(axum::http::HeaderMap, Json<Vec<crate::store::Registry>>)> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let limit = page.limit.unwrap_or(100);
    if !(1..=250).contains(&limit) {
        return Err(ApiError::bad("Choose a page size between 1 and 250."));
    }
    let search = page.search.unwrap_or_default();
    let (name, id) = if let Some(cursor) = page.cursor {
        let cursor = URL_SAFE_NO_PAD.decode(cursor).map_err(ApiError::bad)?;
        let (filter, name, id): (String, String, String) =
            serde_json::from_slice(&cursor).map_err(ApiError::bad)?;
        if filter != search {
            return Err(ApiError::bad("Cursor does not match search."));
        }
        (
            Some(name),
            Some(uuid::Uuid::parse_str(&id).map_err(ApiError::bad)?),
        )
    } else {
        (None, None)
    };
    let mut rows=sqlx::query!(r#"SELECT p.id,p.name,lower(p.name) AS "sort_name!",r.host,(p.secret IS NOT NULL) AS "authenticated!",
        c.provider,c.protocol,c.auth_host,c.auto_sync,c.skip_tls,c.namespace
        FROM registry_profiles p JOIN registries r ON p.registry_id=r.id JOIN registry_config c ON p.id=c.registry_id
        WHERE ($1::text IS NULL OR (lower(p.name),p.id)>($1,$2)) AND
          (strpos(lower(p.name),lower($3))>0 OR strpos(lower(r.host),lower($3))>0)
        ORDER BY lower(p.name),p.id LIMIT $4"#,name,id,search,limit+1)
        .fetch_all(&app.0.database.primary).await?;
    let mut headers = axum::http::HeaderMap::new();
    if rows.len() > limit as usize {
        rows.pop();
        let last = rows.last().unwrap();
        let cursor = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&(&search, &last.sort_name, last.id.to_string()))
                .map_err(anyhow::Error::from)?,
        );
        headers.insert(
            "x-next-cursor",
            cursor.parse().map_err(anyhow::Error::from)?,
        );
    }
    Ok((
        headers,
        Json(
            rows.into_iter()
                .map(|r| crate::store::Registry {
                    id: r.id.to_string(),
                    name: r.name,
                    host: r.host,
                    authenticated: r.authenticated,
                    provider: r.provider,
                    protocol: r.protocol,
                    auth_host: r.auth_host,
                    auto_sync: r.auto_sync,
                    skip_tls: r.skip_tls,
                    namespace: r.namespace,
                })
                .collect(),
        ),
    ))
}

#[cfg(test)]
mod tests;
