use super::*;
use axum::{extract::Request, response::IntoResponse};
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::header::{ACCEPT, AUTHORIZATION};

fn fixture_connection(host: String, provider: &str, auth: Option<Credentials>) -> Connection {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Connection {
        host,
        auth_host: None,
        auth,
        protocol: "http".into(),
        skip_tls: false,
        provider: provider.into(),
        namespace: Some("fixture-org".into()),
    }
}

#[tokio::test]
async fn ghcr_catalog_and_tags_can_be_forbidden_while_exact_manifest_is_readable() {
    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let digest_path = format!("/v2/fixture-org/image/manifests/{DIGEST}");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = listener.local_addr().unwrap().to_string();
    let base = format!("http://{host}");
    let origin = base.clone();
    let app = Router::new().fallback(move |request: Request| {
        let origin = origin.clone();
        let digest_path = digest_path.clone();
        async move {
            let authorization = request.headers().get(AUTHORIZATION).and_then(|value| value.to_str().ok());
            let query = request.uri().query().unwrap_or_default();
            match request.uri().path() {
                "/orgs/fixture-org/packages" => {
                    assert_eq!(authorization, Some("Bearer fixture-pat"));
                    assert!(query.contains("package_type=container"));
                    (StatusCode::FORBIDDEN, Json(json!({"message":"Resource not accessible by personal access token"}))).into_response()
                }
                "/token" => {
                    let basic = format!("Basic {}", STANDARD.encode("fixture-user:fixture-pat"));
                    assert_eq!(authorization, Some(basic.as_str()));
                    assert!(query.contains("service=ghcr.io"));
                    assert!(query.contains("scope=repository%3Afixture-org%2Fimage%3Apull"));
                    Json(json!({"token":"repository-bearer"})).into_response()
                }
                path if path == "/v2/fixture-org/image/tags/list"
                    || path.starts_with("/v2/fixture-org/image/manifests/") => {
                    if authorization.is_none() {
                        return (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, format!(
                            "Bearer realm=\"{origin}/token\",service=\"ghcr.io\",scope=\"repository:fixture-org/image:pull\""
                        ))]).into_response();
                    }
                    assert_eq!(authorization, Some("Bearer repository-bearer"));
                    if path.ends_with("/v1") || path == digest_path {
                        assert!(request.headers()[ACCEPT].to_str().unwrap().contains("application/vnd.oci.image.manifest.v1+json"));
                        let media_type = "application/vnd.oci.image.manifest.v1+json";
                        return ([(reqwest::header::CONTENT_TYPE, media_type)], Json(json!({
                            "schemaVersion": 2,
                            "mediaType": media_type,
                            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": DIGEST, "size": 64},
                            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": DIGEST, "size": 128}]
                        }))).into_response();
                    }
                    (StatusCode::FORBIDDEN, Json(json!({"errors":[{"code":"DENIED","message":"denied"}]}))).into_response()
                }
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let connection = fixture_connection(
        host,
        "ghcr",
        Some(Credentials {
            username: "fixture-user".into(),
            password: "fixture-pat".into(),
        }),
    );
    let catalog = github_catalog(&connection, &client(false).unwrap(), &base, "fixture-org")
        .await
        .unwrap_err();
    assert!(
        catalog
            .to_string()
            .contains("GitHub package catalog returned HTTP 403")
    );
    let tags = get(
        &connection,
        "/v2/fixture-org/image/tags/list",
        &[],
        OciOperation::Tags,
    )
    .await
    .unwrap_err();
    assert!(
        tags.to_string()
            .contains("OCI tag listing returned HTTP 403")
    );
    let exact = |tag| {
        ImageReference::parse(&format!("fixture-org/image:{tag}"), Some(&connection.host)).unwrap()
    };
    manifest(&connection, &exact("v1")).await.unwrap();
    let by_digest = ImageReference::parse(
        &format!("fixture-org/image@{DIGEST}"),
        Some(&connection.host),
    )
    .unwrap();
    manifest(&connection, &by_digest).await.unwrap();
    let denied = manifest(&connection, &exact("denied")).await.unwrap_err();
    assert!(
        denied
            .to_string()
            .contains("Exact image manifest lookup returned HTTP 403")
    );
    server.abort();
}

#[tokio::test]
#[ignore = "requires the documented disposable Forgejo fixture"]
async fn forgejo_private_package_with_scoped_token() {
    let host = std::env::var("CERTHIA_TEST_FORGEJO_HOST").unwrap();
    let path = std::env::var_os("CERTHIA_TEST_FORGEJO_TOKEN_FILE").unwrap();
    let password = tokio::fs::read_to_string(path).await.unwrap();
    let anonymous = fixture_connection(host.clone(), "forgejo", None);
    let reference = ImageReference::parse("fixture-org/nested/demo:v1", Some(&host)).unwrap();
    assert!(manifest(&anonymous, &reference).await.is_err());
    let connection = fixture_connection(
        host,
        "forgejo",
        Some(Credentials {
            username: "registry-admin".into(),
            password: password.trim().into(),
        }),
    );
    assert_eq!(
        provider_catalog(&connection).await.unwrap().unwrap(),
        ["fixture-org/nested/demo"]
    );
    let tags: Value = get(
        &connection,
        "/v2/fixture-org/nested/demo/tags/list",
        &[],
        OciOperation::Tags,
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(tags["tags"], json!(["v1"]));
    manifest(&connection, &reference).await.unwrap();
}

#[tokio::test]
async fn unsaved_workload_marker_cannot_mint_a_cloud_credential() {
    let auth = Credentials {
        username: cloud::MARKER.into(),
        password: cloud::MARKER.into(),
    };
    let result = pull_credentials("fixture.azurecr.io", Some(auth)).await;
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("Save a verified HTTPS registry connection")
    );
    assert!(cloud::is_scanner_marker(&cloud::scanner_marker().unwrap()));
}
