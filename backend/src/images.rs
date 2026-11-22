use crate::{
    ApiError, ApiResult, App, ImageReference,
    operations::repository,
    scanner::{Credentials, docker_config, run},
    store::{Job, ScanDetail},
};
use anyhow::{Result, anyhow, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{StatusCode, header},
    response::Response,
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{path::PathBuf, time::Duration};
use tempfile::TempDir;
use tokio::process::Command;
use tokio_util::io::ReaderStream;

pub fn routes() -> Router<App> {
    Router::new()
        .route("/images/{id}/archive", get(download_image))
        .route("/images/{id}/publish", post(publish_image))
        .route("/images/{id}/layers", get(layers))
        .route("/images/{id}/layers/{index}/files", get(layer_files))
}

pub struct Source {
    pub reference: String,
    pub transport: String,
    pub platform: String,
    pub auth: Option<Credentials>,
    pub host: String,
    pub insecure: bool,
}

pub async fn credentials_for(
    app: &App,
    id: Option<&str>,
    host: &str,
) -> Result<Option<Credentials>> {
    let Some(id) = id else {
        return Ok(None);
    };
    let (owner, value) = crate::registries::credential_record(app, id)
        .await?
        .ok_or_else(|| anyhow!("The saved registry was removed."))?;
    if owner != host {
        bail!("The selected connection is for a different registry.");
    }
    value
        .map(|secret| app.0.vault.open_secret(host, &secret))
        .transpose()
}

pub async fn load(app: &App, id: &str) -> ApiResult<(Job, ScanDetail)> {
    let detail = app
        .0
        .database
        .scan(id)
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    let job = app
        .0
        .database
        .replay(id)
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    Ok((job, detail))
}

pub async fn source(app: &App, job: &Job, detail: &ScanDetail) -> Result<Source> {
    let platform = job.platform.clone();
    if job.source == "docker" {
        return Ok(Source {
            transport: format!("docker-daemon:{}", job.reference),
            reference: job.reference.clone(),
            platform,
            auth: None,
            host: String::new(),
            insecure: false,
        });
    }
    if job.source == "archive" {
        let path = app.0.data.join("archives").join(&job.id);
        if !path.is_file() {
            bail!("The original archive is unavailable. Upload it again.");
        }
        return Ok(Source {
            transport: format!("docker-archive:{}", path.display()),
            reference: job.reference.clone(),
            platform,
            auth: None,
            host: String::new(),
            insecure: false,
        });
    }
    let digest = detail
        .report
        .as_ref()
        .and_then(|report| report.digest.as_deref());
    let pinned = digest.map(|digest| format!("{}@{digest}", repository(&job.reference)));
    let reference = ImageReference::parse(pinned.as_deref().unwrap_or(&job.reference), None)?;
    let auth = credentials_for(app, job.registry_id.as_deref(), &reference.host).await?;
    Ok(Source {
        transport: format!("docker://{}", reference.value),
        reference: reference.value,
        platform,
        auth,
        host: reference.host,
        insecure: crate::registries::insecure(app, job.registry_id.as_deref()).await?,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Destination {
    pub reference: String,
    pub registry_id: Option<String>,
}

pub async fn destination(
    app: &App,
    input: Destination,
) -> ApiResult<(ImageReference, Option<Credentials>, bool)> {
    let owner = match input.registry_id.as_deref() {
        Some(id) => crate::registries::credential_record(app, id)
            .await?
            .map(|r| r.0),
        None => None,
    };
    if input.registry_id.is_some() && owner.is_none() {
        return Err(ApiError::missing("Destination registry not found."));
    }
    let reference =
        ImageReference::parse(&input.reference, owner.as_deref()).map_err(ApiError::bad)?;
    if reference.value.contains('@') || !input.reference.contains('/') {
        return Err(ApiError::bad(
            "Enter a destination registry image with a tag.",
        ));
    }
    let auth = credentials_for(app, input.registry_id.as_deref(), &reference.host)
        .await
        .map_err(ApiError::bad)?;
    Ok((
        reference,
        auth,
        crate::registries::insecure(app, input.registry_id.as_deref()).await?,
    ))
}

fn skopeo(platform: &str) -> Command {
    let mut command = Command::new("skopeo");
    let mut components = platform.split('/');
    if let (Some(os), Some(arch)) = (components.next(), components.next()) {
        command
            .arg("--override-os")
            .arg(os)
            .arg("--override-arch")
            .arg(arch);
        if let Some(variant) = components.next() {
            command.arg("--override-variant").arg(variant);
        }
    }
    if let Ok(socket) = std::env::var("CERTHIA_DOCKER_SOCKET") {
        command.env("DOCKER_HOST", format!("unix://{socket}"));
    }
    command
}

pub async fn copy(
    source: Source,
    transport: &str,
    host: &str,
    auth: Option<Credentials>,
    insecure: bool,
) -> Result<Option<String>> {
    let dir = tempfile::tempdir()?;
    let source_file = dir.path().join("source.json");
    let destination_file = dir.path().join("destination.json");
    let source_auth = crate::registries::pull_credentials(&source.host, source.auth).await?;
    let destination_auth = crate::registries::pull_credentials(host, auth).await?;
    docker_config(&source_file, &source.host, source_auth)?;
    docker_config(&destination_file, host, destination_auth)?;
    let mut command = skopeo(&source.platform);
    command
        .arg("copy")
        .arg("--quiet")
        .arg("--src-authfile")
        .arg(source_file)
        .arg("--dest-authfile")
        .arg(destination_file);
    if source.insecure {
        command.arg("--src-tls-verify=false");
    }
    if insecure {
        command.arg("--dest-tls-verify=false");
    }
    if transport.starts_with("dir:") {
        command.arg("--dest-decompress");
    }
    let digest_file = dir.path().join("published-digest");
    if transport.starts_with("docker://") {
        command.arg("--digestfile").arg(&digest_file);
    }
    command.arg(source.transport).arg(transport);
    run(command, "Skopeo", Duration::from_secs(30 * 60)).await?;
    Ok(tokio::fs::read_to_string(digest_file)
        .await
        .ok()
        .map(|digest| digest.trim().to_owned()))
}

pub async fn attachment(
    path: PathBuf,
    filename: &str,
    guard: Option<TempDir>,
) -> ApiResult<Response> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(anyhow::Error::from)?;
    let size = file.metadata().await.map_err(anyhow::Error::from)?.len();
    let stream = ReaderStream::new(file).map(move |chunk| {
        let _keep_alive = &guard;
        chunk
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-tar")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .header(header::CONTENT_LENGTH, size)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(stream))
        .map_err(|error| anyhow::Error::from(error).into())
}

async fn download_image(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Response> {
    let (job, detail) = load(&app, &id).await?;
    let source = source(&app, &job, &detail).await.map_err(ApiError::bad)?;
    let dir = tempfile::tempdir_in(app.0.data.join("archives")).map_err(anyhow::Error::from)?;
    let path = dir.path().join("image.tar");
    if job.source == "archive" {
        return attachment(
            app.0.data.join("archives").join(&id),
            "container-image.tar",
            None,
        )
        .await;
    }
    let tag = if job.reference.contains('@') || job.source == "docker" {
        "digestdesk:exported"
    } else {
        &job.reference
    };
    copy(
        source,
        &format!("docker-archive:{}:{tag}", path.display()),
        "",
        None,
        false,
    )
    .await
    .map_err(ApiError::bad)?;
    app.0
        .database
        .audit("image.downloaded", &id, &job.reference)
        .await?;
    attachment(path, "container-image.tar", Some(dir)).await
}

async fn publish_image(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<Destination>,
) -> ApiResult<Json<Value>> {
    let (job, detail) = load(&app, &id).await?;
    let source = source(&app, &job, &detail).await.map_err(ApiError::bad)?;
    let (target, auth, insecure) = destination(&app, input).await?;
    if job.reference == target.value || source.reference == target.value {
        return Err(ApiError::bad(
            "Choose a destination distinct from the source image.",
        ));
    }
    copy(
        source,
        &format!("docker://{}", target.value),
        &target.host,
        auth,
        insecure,
    )
    .await
    .map_err(ApiError::bad)?;
    app.0
        .database
        .audit("image.published", &id, &target.value)
        .await?;
    Ok(Json(json!({"reference":target.value})))
}

async fn layers(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let (job, detail) = load(&app, &id).await?;
    let source = source(&app, &job, &detail).await.map_err(ApiError::bad)?;
    let dir = tempfile::tempdir().map_err(anyhow::Error::from)?;
    let file = dir.path().join("config.json");
    let auth = crate::registries::pull_credentials(&source.host, source.auth).await?;
    docker_config(&file, &source.host, auth)?;
    let mut command = skopeo(&source.platform);
    command
        .arg("inspect")
        .arg("--raw")
        .arg("--authfile")
        .arg(&file);
    if source.insecure {
        command.arg("--tls-verify=false");
    }
    command.arg(&source.transport);
    let output = run(command, "Skopeo", Duration::from_secs(30))
        .await
        .map_err(ApiError::bad)?;
    let mut manifest: Value =
        serde_json::from_slice(&output.stdout).map_err(anyhow::Error::from)?;
    if let Some(entries) = manifest["manifests"].as_array() {
        let digest = entries
            .iter()
            .find(|entry| {
                let candidate = &entry["platform"];
                let architecture = candidate["architecture"].as_str().unwrap_or_default();
                let os = candidate["os"].as_str().unwrap_or_default();
                let value = format!("{os}/{architecture}");
                job.platform == value
                    || job.platform
                        == format!(
                            "{value}/{}",
                            candidate["variant"].as_str().unwrap_or_default()
                        )
            })
            .and_then(|entry| entry["digest"].as_str())
            .ok_or_else(|| ApiError::bad("The image index has no manifest for this platform."))?;
        let reference =
            ImageReference::parse(&format!("{}@{digest}", repository(&job.reference)), None)
                .map_err(ApiError::bad)?;
        let mut command = skopeo(&source.platform);
        command
            .arg("inspect")
            .arg("--raw")
            .arg("--authfile")
            .arg(&file);
        if source.insecure {
            command.arg("--tls-verify=false");
        }
        command.arg(format!("docker://{}", reference.value));
        let output = run(command, "Skopeo", Duration::from_secs(30))
            .await
            .map_err(ApiError::bad)?;
        manifest = serde_json::from_slice(&output.stdout).map_err(anyhow::Error::from)?;
    }
    let layers = manifest["layers"].as_array().cloned().unwrap_or_default();
    let compressed = layers
        .iter()
        .filter_map(|layer| layer["size"].as_u64())
        .sum::<u64>();
    let mut digests = std::collections::BTreeSet::new();
    let repeated_bytes = layers
        .iter()
        .filter_map(|layer| {
            let repeated = !digests.insert(layer["digest"].as_str()?);
            repeated.then(|| layer["size"].as_u64()).flatten()
        })
        .sum::<u64>();
    Ok(Json(
        json!({"layers":layers,"compressedBytes":compressed,"repeatedBytes":repeated_bytes}),
    ))
}

async fn layer_files(
    State(app): State<App>,
    Path((id, index)): Path<(String, usize)>,
) -> ApiResult<Json<Value>> {
    if index >= 1000 {
        return Err(ApiError::missing("Layer not found."));
    }
    let (job, detail) = load(&app, &id).await?;
    let source = source(&app, &job, &detail).await.map_err(ApiError::bad)?;
    let dir = tempfile::tempdir_in(app.0.data.join("archives")).map_err(anyhow::Error::from)?;
    copy(
        source,
        &format!("dir:{}", dir.path().display()),
        "",
        None,
        false,
    )
    .await
    .map_err(ApiError::bad)?;
    let files = tokio::task::spawn_blocking(move || inspect_layer(dir, index))
        .await
        .map_err(anyhow::Error::from)??;
    Ok(Json(files))
}

fn inspect_layer(dir: TempDir, index: usize) -> ApiResult<Value> {
    use std::io::Read;
    let manifest_file =
        std::fs::File::open(dir.path().join("manifest.json")).map_err(anyhow::Error::from)?;
    let manifest: Value = serde_json::from_reader(manifest_file.take(5 * 1024 * 1024))
        .map_err(anyhow::Error::from)?;
    let digest = manifest["layers"][index]["digest"]
        .as_str()
        .and_then(|value| value.strip_prefix("sha256:"))
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| ApiError::missing("Layer not found."))?;
    let layer = std::fs::File::open(dir.path().join(digest)).map_err(anyhow::Error::from)?;
    let bytes = layer.metadata().map_err(anyhow::Error::from)?.len();
    let mut archive = tar::Archive::new(layer);
    let mut files = Vec::new();
    for file in archive
        .entries_with_seek()
        .map_err(anyhow::Error::from)?
        .take(501)
    {
        let file = file.map_err(anyhow::Error::from)?;
        let path = file.path().map_err(anyhow::Error::from)?;
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let entry = file.header().entry_type();
        let kind = if filename.starts_with(".wh.") {
            "removed"
        } else if entry.is_dir() {
            "directory"
        } else if entry.is_symlink() || entry.is_hard_link() {
            "link"
        } else if entry.is_file() {
            "file"
        } else {
            "special"
        };
        files.push(json!({
            "path": path.to_string_lossy().chars().take(1024).collect::<String>(),
            "size": file.size(), "type": kind,
        }));
    }
    let truncated = files.len() > 500;
    files.truncate(500);
    Ok(json!({"index":index,"files":files,"uncompressedBytes":bytes,"truncated":truncated}))
}

pub async fn pin(
    reference: &ImageReference,
    platform: &str,
    auth: Option<Credentials>,
    insecure: bool,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("auth.json");
    let auth = crate::registries::pull_credentials(&reference.host, auth).await?;
    docker_config(&file, &reference.host, auth)?;
    let mut command = skopeo(platform);
    command
        .arg("inspect")
        .arg("--raw")
        .arg("--authfile")
        .arg(&file);
    if insecure {
        command.arg("--tls-verify=false");
    }
    command.arg(format!("docker://{}", reference.value));
    let output = run(command, "Skopeo", Duration::from_secs(30)).await?;
    let manifest: Value = serde_json::from_slice(&output.stdout)?;
    if manifest["schemaVersion"] != 2 {
        bail!("The registry did not return an image manifest.");
    }
    let digest = if let Some(items) = manifest["manifests"].as_array() {
        items
            .iter()
            .filter_map(|item| {
                let metadata = &item["platform"];
                let family = format!(
                    "{}/{}",
                    metadata["os"].as_str()?,
                    metadata["architecture"].as_str()?
                );
                let variant = metadata["variant"]
                    .as_str()
                    .map(|value| format!("{family}/{value}"));
                (platform == family || variant.as_deref() == Some(platform))
                    .then(|| item["digest"].as_str())
                    .flatten()
            })
            .next()
            .ok_or_else(|| anyhow!("The image has no manifest for {platform}."))?
            .to_owned()
    } else {
        {
            use std::fmt::Write;
            let mut value = String::from("sha256:");
            for byte in Sha256::digest(&output.stdout) {
                write!(value, "{byte:02x}").expect("infallible write to String");
            }
            value
        }
    };
    let pinned =
        ImageReference::parse(&format!("{}@{digest}", repository(&reference.value)), None)?;
    Ok(pinned.value)
}
