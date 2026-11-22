use crate::{ApiError, ApiResult, App, ImageReference, ImageTarget, validate_platform};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{StatusCode, header},
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};
use uuid::Uuid;

pub fn routes() -> Router<App> {
    Router::new()
        .route("/discover/docker", get(images))
        .route("/discover/swarm", get(swarm))
        .route("/discover/kubernetes", get(kubernetes))
        .route("/discover/kubernetes/namespaces", get(namespaces))
        .route("/scans/archive", post(archive))
}

pub fn socket() -> ApiResult<PathBuf> {
    std::env::var_os("CERTHIA_DOCKER_SOCKET")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.exists())
        .ok_or_else(|| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "Configure CERTHIA_DOCKER_SOCKET to use the local Docker engine.".into(),
            )
        })
}

async fn docker(path: &str) -> ApiResult<Vec<Value>> {
    let client = reqwest::Client::builder()
        .unix_socket(socket()?)
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(anyhow::Error::from)?;
    let response = client
        .get(format!("http://localhost{path}"))
        .send()
        .await
        .map_err(|_| ApiError::bad("Could not contact the Docker engine."))?;
    if !response.status().is_success() {
        return Err(ApiError::bad(
            "The Docker engine rejected the request. Check socket access and Swarm manager mode.",
        ));
    }
    response
        .json()
        .await
        .map_err(|_| ApiError::bad("The Docker engine returned an invalid response."))
}

async fn images() -> ApiResult<Json<Value>> {
    let items = docker("/images/json").await?;
    let data = items.iter().filter_map(|item| {
        let id = item["Id"].as_str()?;
        let references = item["RepoTags"].as_array().map(|refs| refs.iter().filter_map(Value::as_str).collect::<Vec<_>>()).unwrap_or_default();
        Some(json!({ "reference": id, "label": references.first().unwrap_or(&id), "tags": references, "sizeBytes": item["Size"] }))
    }).collect::<Vec<_>>();
    Ok(Json(json!(data)))
}

async fn swarm() -> ApiResult<Json<Value>> {
    let items = docker("/services").await?;
    let data = items
        .iter()
        .filter_map(|item| {
            let reference = item["Spec"]["TaskTemplate"]["ContainerSpec"]["Image"].as_str()?;
            let name = item["Spec"]["Name"].as_str().unwrap_or(reference);
            Some(json!({"reference": reference, "label": name}))
        })
        .collect::<Vec<_>>();
    Ok(Json(json!(data)))
}

#[derive(Deserialize)]
struct Namespace {
    namespace: Option<String>,
}

fn kube_command(resource: &str) -> ApiResult<Command> {
    let kubeconfig = std::env::var_os("KUBECONFIG").ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "Mount a kubeconfig and set KUBECONFIG to discover running pods.".into(),
        )
    })?;
    let mut command = Command::new("kubectl");
    command.env("KUBECONFIG", kubeconfig).args([
        "get",
        resource,
        "-o",
        "json",
        "--request-timeout=10s",
    ]);
    Ok(command)
}

async fn kube_list(mut command: Command) -> ApiResult<Value> {
    let output = tokio::time::timeout(Duration::from_secs(15), command.kill_on_drop(true).output())
        .await
        .map_err(|_| ApiError::bad("Kubernetes discovery timed out."))?
        .map_err(|_| ApiError::bad("kubectl is unavailable."))?;
    if !output.status.success() {
        return Err(ApiError::bad(
            "Kubernetes rejected discovery. Verify kubeconfig and list permissions.",
        ));
    }
    let payload: Value = serde_json::from_slice(&output.stdout).map_err(anyhow::Error::from)?;
    Ok(payload)
}

async fn namespaces() -> ApiResult<Json<Value>> {
    let payload = kube_list(kube_command("namespaces")?).await?;
    let mut names = payload["items"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["metadata"]["name"].as_str())
        .collect::<Vec<_>>();
    names.sort_unstable();
    Ok(Json(json!(names)))
}

async fn kubernetes(Query(input): Query<Namespace>) -> ApiResult<Json<Value>> {
    let mut command = kube_command("pods")?;
    match input.namespace.as_deref().filter(|name| !name.is_empty()) {
        Some(name)
            if name.len() <= 63
                && !name.starts_with('-')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') =>
        {
            command.arg("--namespace").arg(name);
        }
        Some(_) => return Err(ApiError::bad("Enter a valid Kubernetes namespace.")),
        None => {
            command.arg("--all-namespaces");
        }
    }
    let payload = kube_list(command).await?;
    let mut found = BTreeMap::<String, serde_json::Value>::new();
    for pod in payload["items"].as_array().into_iter().flatten() {
        let namespace = pod["metadata"]["namespace"].as_str().unwrap_or("default");
        let name = pod["metadata"]["name"].as_str().unwrap_or("pod");
        for key in ["containers", "initContainers"] {
            for container in pod["spec"][key].as_array().into_iter().flatten() {
                if let Some(reference) = container["image"].as_str() {
                    found.entry(reference.to_owned()).or_insert_with(|| json!({
                        "reference": reference, "label": format!("{namespace}/{name}"), "namespace": namespace
                    }));
                }
            }
        }
    }
    Ok(Json(json!(found.into_values().collect::<Vec<_>>())))
}

#[derive(Deserialize)]
struct ArchiveInput {
    reference: String,
    platform: String,
    scanners: Option<String>,
    priority: Option<i32>,
}

async fn archive(
    State(app): State<App>,
    Query(input): Query<ArchiveInput>,
    request: Request,
) -> ApiResult<(StatusCode, Json<Value>)> {
    const MAX: usize = 2 * 1024 * 1024 * 1024;
    validate_platform(&input.platform)?;
    let reference = ImageReference::parse(&input.reference, None).map_err(ApiError::bad)?;
    let (scanners, priority) = crate::jobs::validate(
        input.scanners.map(|value| {
            value
                .split(',')
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
                .collect()
        }),
        input.priority,
    )?;
    let mime = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if ![
        "application/x-tar",
        "application/octet-stream",
        "application/gzip",
    ]
    .contains(&mime)
    {
        return Err(ApiError::bad("Upload a Docker image archive."));
    }
    let id = Uuid::now_v7().to_string();
    let destination = app.0.data.join("archives").join(&id);
    // A guarded partial file is removed if the request is disconnected or interrupted.
    let mut partial = tempfile::NamedTempFile::new_in(app.0.data.join("archives"))
        .map_err(anyhow::Error::from)?;
    let handle = partial.reopen().map_err(anyhow::Error::from)?;
    let mut file = tokio::fs::File::from_std(handle);
    let mut data = request.into_body().into_data_stream();
    let mut received: usize = 0;
    while let Some(chunk) = data.next().await {
        let chunk = chunk.map_err(|_| ApiError::bad("The upload was interrupted."))?;
        received = received.saturating_add(chunk.len());
        if received > MAX {
            return Err(ApiError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "The archive exceeds 2 GiB.".into(),
            ));
        }
        file.write_all(&chunk).await.map_err(anyhow::Error::from)?;
    }
    if received < 512 {
        return Err(ApiError::bad("The archive is incomplete."));
    }
    file.flush().await.map_err(anyhow::Error::from)?;
    file.sync_all().await.map_err(anyhow::Error::from)?;
    drop(file);
    partial
        .as_file_mut()
        .sync_all()
        .map_err(anyhow::Error::from)?;
    partial.persist(&destination).map_err(anyhow::Error::from)?;
    let target = ImageTarget {
        reference: reference.value,
        platform: input.platform,
        registry_id: None,
        source: "archive".into(),
        scanners,
        priority,
    };
    let queued = crate::jobs::enqueue_with_id(&app, &id, &target).await;
    if !matches!(queued, Ok(true)) {
        let _ = tokio::fs::remove_file(destination).await;
        queued?;
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "The scan queue is full.".into(),
        ));
    }
    app.0
        .database
        .audit("archive.queued", &id, &target.reference)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({"id":id}))))
}
