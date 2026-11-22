use crate::{ApiError, ApiResult, App, ImageReference, ImageTarget, validate_platform};
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    http::{StatusCode, header},
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::Duration,
};
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
    let (items, containers) = tokio::join!(docker("/images/json"), docker("/containers/json"));
    Ok(Json(json!(docker_images(
        &items?,
        containers.as_deref().ok()
    ))))
}

fn docker_images(items: &[Value], containers: Option<&[Value]>) -> Vec<Value> {
    let running = containers.map(|containers| {
        containers
            .iter()
            .filter(|item| item["State"] == "running")
            .filter_map(|item| item["ImageID"].as_str())
            .collect::<BTreeSet<_>>()
    });
    items
        .iter()
        .filter_map(|item| {
            let id = item["Id"].as_str()?;
            let references = item["RepoTags"]
                .as_array()
                .map(|refs| refs.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                .unwrap_or_default();
            Some(json!({
                "reference": id, "label": references.first().unwrap_or(&id),
                "tags": references, "sizeBytes": item["Size"], "running": running.as_ref().map(|ids| ids.contains(id))
            }))
        })
        .collect()
}

async fn swarm() -> ApiResult<Json<Value>> {
    let items = docker("/services").await?;
    Ok(Json(json!(swarm_images(&items))))
}

fn swarm_images(items: &[Value]) -> Vec<Value> {
    items
        .iter()
        .filter_map(|item| {
            let reference = item["Spec"]["TaskTemplate"]["ContainerSpec"]["Image"].as_str()?;
            let name = item["Spec"]["Name"].as_str().unwrap_or(reference);
            let parsed = ImageReference::parse(reference, None).ok();
            let digest = parsed
                .as_ref()
                .and_then(|image| image.value.split_once('@').map(|(_, digest)| digest));
            Some(
                json!({"reference": reference, "label": name, "digest": digest,
                "registryHost": parsed.as_ref().map(|image| &image.host)}),
            )
        })
        .collect()
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

pub fn validate_namespace(namespace: Option<&str>) -> ApiResult<Option<&str>> {
    match namespace.filter(|name| !name.is_empty()) {
        Some(name)
            if name.len() <= 63
                && !name.starts_with('-')
                && !name.ends_with('-')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') =>
        {
            Ok(Some(name))
        }
        Some(_) => Err(ApiError::bad("Enter a valid Kubernetes namespace.")),
        None => Ok(None),
    }
}

fn namespaced_command(resource: &str, namespace: Option<&str>) -> ApiResult<Command> {
    let mut command = kube_command(resource)?;
    match validate_namespace(namespace)? {
        Some(name) => command.arg("--namespace").arg(name),
        None => command.arg("--all-namespaces"),
    };
    Ok(command)
}

async fn kubernetes(Query(input): Query<Namespace>) -> ApiResult<Json<Value>> {
    Ok(Json(json!(
        kubernetes_images(input.namespace.as_deref()).await?
    )))
}

async fn kubernetes_images(namespace: Option<&str>) -> ApiResult<Vec<PodImage>> {
    let pods = kube_list(namespaced_command("pods", namespace)?).await?;
    if !pods["items"].is_array() {
        return Err(ApiError::bad("Kubernetes did not return a pod list."));
    }
    let controller_kinds = items(&pods)
        .filter_map(controller)
        .filter_map(|owner| owner["kind"].as_str())
        .collect::<BTreeSet<_>>();
    let (replica_sets, jobs) = tokio::join!(
        list_owners(
            "replicasets.apps",
            namespace,
            controller_kinds.contains("ReplicaSet")
        ),
        list_owners("jobs.batch", namespace, controller_kinds.contains("Job")),
    );
    Ok(pod_images(&pods, &[replica_sets, jobs]))
}

pub type RuntimeImages = BTreeMap<String, BTreeSet<String>>;

pub async fn kubernetes_observation(
    namespace: Option<&str>,
    host: Option<&str>,
    previous: &RuntimeImages,
) -> ApiResult<(RuntimeImages, BTreeSet<String>)> {
    let mut next = RuntimeImages::new();
    let mut uncertain = BTreeSet::new();
    let mut changed = BTreeSet::new();
    for image in kubernetes_images(namespace).await? {
        let observed = ImageReference::parse(&image.reference, None).ok();
        for usage in image.usages {
            if let Some(host) = host {
                let registry_matches = if usage.runtime_digest {
                    observed.as_ref().is_some_and(|image| image.host == host)
                } else {
                    ImageReference::parse(&usage.declared_image, None)
                        .is_ok_and(|image| image.host == host)
                };
                if !registry_matches {
                    continue;
                }
            }
            let key = [
                usage.namespace,
                usage.workload_kind,
                usage.workload_name,
                usage.container_type.to_owned(),
                usage.container,
            ]
            .join("/");
            if let Some(observed) = observed.as_ref().filter(|_| usage.runtime_digest) {
                if previous
                    .get(&key)
                    .is_none_or(|digests| !digests.contains(&observed.value))
                {
                    changed.insert(observed.value.clone());
                }
                next.entry(key).or_default().insert(observed.value.clone());
            } else {
                uncertain.insert(key);
            }
        }
    }
    for key in uncertain {
        if let Some(known) = previous.get(&key) {
            next.entry(key).or_default().extend(known.iter().cloned());
        }
    }
    Ok((next, changed))
}

async fn list_owners(resource: &str, namespace: Option<&str>, needed: bool) -> Value {
    if !needed {
        return Value::Null;
    }
    // Pod-only RBAC still provides the immediate controller for each pod.
    match namespaced_command(resource, namespace) {
        Ok(command) => kube_list(command).await.unwrap_or(Value::Null),
        Err(_) => Value::Null,
    }
}

fn items(list: &Value) -> impl Iterator<Item = &Value> {
    list["items"].as_array().into_iter().flatten()
}

fn controller(object: &Value) -> Option<&Value> {
    object["metadata"]["ownerReferences"]
        .as_array()?
        .iter()
        .find(|owner| owner["controller"] == true)
}

#[derive(Serialize)]
struct PodImage {
    reference: String,
    label: String,
    namespace: String,
    usages: BTreeSet<PodImageUsage>,
}

#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
struct PodImageUsage {
    namespace: String,
    pod: String,
    workload_kind: String,
    workload_name: String,
    container: String,
    container_type: &'static str,
    declared_image: String,
    runtime_digest: bool,
}

fn pod_images(pods: &Value, owner_lists: &[Value]) -> Vec<PodImage> {
    let parents = owner_lists
        .iter()
        .flat_map(items)
        .filter_map(|object| Some((object["metadata"]["uid"].as_str()?, controller(object)?)))
        .collect::<BTreeMap<_, _>>();
    let mut found = BTreeMap::<String, PodImage>::new();
    for pod in items(pods) {
        let namespace = pod["metadata"]["namespace"].as_str().unwrap_or("default");
        let Some(name) = pod["metadata"]["name"].as_str() else {
            continue;
        };
        let owner = controller(pod).map(|owner| {
            owner["uid"]
                .as_str()
                .and_then(|uid| parents.get(uid).copied())
                .unwrap_or(owner)
        });
        let workload_kind = owner
            .and_then(|owner| owner["kind"].as_str())
            .unwrap_or("Pod");
        let workload_name = owner
            .and_then(|owner| owner["name"].as_str())
            .unwrap_or(name);
        for (spec_key, status_key, container_type) in [
            ("containers", "containerStatuses", "app"),
            ("initContainers", "initContainerStatuses", "init"),
            (
                "ephemeralContainers",
                "ephemeralContainerStatuses",
                "ephemeral",
            ),
        ] {
            let statuses = pod["status"][status_key].as_array();
            for container in pod["spec"][spec_key].as_array().into_iter().flatten() {
                let (Some(container_name), Some(declared)) =
                    (container["name"].as_str(), container["image"].as_str())
                else {
                    continue;
                };
                let status = statuses.and_then(|entries| {
                    entries.iter().find(|entry| entry["name"] == container_name)
                });
                let pinned = status.and_then(|status| runtime_reference(declared, status));
                let runtime_digest = pinned.is_some();
                let reference = pinned.unwrap_or_else(|| declared.to_owned());
                let key = ImageReference::parse(&reference, None)
                    .map_or_else(|_| reference.clone(), |image| image.value);
                let image = found.entry(key).or_insert_with(|| PodImage {
                    reference: reference.clone(),
                    label: String::new(),
                    namespace: namespace.to_owned(),
                    usages: BTreeSet::new(),
                });
                if runtime_digest {
                    image.reference = reference;
                }
                image.usages.insert(PodImageUsage {
                    namespace: namespace.to_owned(),
                    pod: name.to_owned(),
                    workload_kind: workload_kind.to_owned(),
                    workload_name: workload_name.to_owned(),
                    container: container_name.to_owned(),
                    container_type,
                    declared_image: declared.to_owned(),
                    runtime_digest,
                });
            }
        }
    }
    found
        .into_values()
        .map(|mut image| {
            let workloads = image
                .usages
                .iter()
                .map(|usage| (&usage.namespace, &usage.workload_kind, &usage.workload_name))
                .collect::<BTreeSet<_>>();
            if let Some((namespace, kind, name)) = workloads.first() {
                image.namespace = (*namespace).clone();
                image.label = if workloads.len() == 1 {
                    format!("{namespace}/{name} ({kind})")
                } else {
                    format!("{} workloads", workloads.len())
                };
            }
            image
        })
        .collect()
}

fn runtime_reference(declared: &str, status: &Value) -> Option<String> {
    let declared = ImageReference::parse(declared, None).ok()?.value;
    let id = status["imageID"].as_str()?;
    let pull_reference = match id.split_once("://") {
        Some(("docker-pullable" | "docker" | "containerd" | "cri-o", reference)) => reference,
        Some(_) => return None,
        None => id,
    };
    // A bare runtime ID may refer to the image config rather than a pullable manifest.
    let resolved = ImageReference::parse(pull_reference, None).ok()?.value;
    let (repository, _) = resolved.split_once('@')?;
    let declared_repository = declared.split_once('@').map_or_else(
        || declared.rsplit_once(':').map(|(repository, _)| repository),
        |(repository, _)| Some(repository),
    )?;
    if repository != declared_repository {
        return None;
    }
    // A different tagged status image can be left over from before a pod spec update.
    if let Some(status_image) = status["image"]
        .as_str()
        .and_then(|image| ImageReference::parse(image, None).ok())
    {
        if status_image.value != declared && status_image.value != resolved {
            return None;
        }
    }
    Some(resolved)
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

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NEW: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn kubernetes_groups_every_usage_and_distinguishes_rollout_digests() {
        let old = format!("registry.test/team/api@{OLD}");
        let new = format!("registry.test/team/api@{NEW}");
        let declared = "registry.test/team/api:stable";
        let replica = json!({"uid":"rs1","kind":"ReplicaSet","name":"api-rs","controller":true});
        let pod = |namespace: &str, name: &str, owner: Value, image: &str| {
            json!({
                "metadata":{"namespace":namespace,"name":name,"ownerReferences":[owner]},
                "spec":{"containers":[{"name":"api","image":declared}],
                    "initContainers":[{"name":"setup","image":declared}]},
                "status":{"containerStatuses":[{"name":"other","imageID":"docker://sha256:ignored"},
                    {"name":"api","image":declared,"imageID":format!("docker-pullable://{image}")}],
                    "initContainerStatuses":[{"name":"setup","imageID":old}]}
            })
        };
        let pods = json!({"items":[
            pod("staging", "debug", Value::Null, &old),
            pod("production", "api-1", replica.clone(), &old),
            pod("production", "api-2", replica, &new)
        ]});
        let owners = json!({"items":[{"metadata":{"uid":"rs1","ownerReferences":[
            {"controller":false,"kind":"ConfigMap","name":"unrelated"},
            {"controller":true,"kind":"Deployment","name":"api"}
        ]}}]});
        let images = pod_images(&pods, &[owners]);
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].reference, old);
        assert_eq!(images[0].usages.len(), 5);
        assert_eq!(images[0].label, "2 workloads");
        assert!(images[0].usages.iter().any(|usage| {
            usage.pod == "api-2" && usage.container_type == "init" && usage.runtime_digest
        }));
        assert!(
            images[0]
                .usages
                .iter()
                .any(|usage| { usage.namespace == "staging" && usage.workload_kind == "Pod" })
        );
        assert_eq!(images[1].reference, new);
        let usage = images[1].usages.first().unwrap();
        assert_eq!(usage.workload_kind, "Deployment");
        assert_eq!(usage.workload_name, "api");
        assert_eq!(usage.pod, "api-2");

        let without_owner_access = pod_images(&pods, &[]);
        assert_eq!(
            without_owner_access[1]
                .usages
                .first()
                .unwrap()
                .workload_kind,
            "ReplicaSet"
        );
    }

    #[test]
    fn kubernetes_falls_back_for_unpullable_or_unrelated_runtime_ids() {
        let declared = "registry.test:5000/team/api:stable";
        for (id, status_image) in [
            (format!("containerd://{OLD}"), declared),
            (format!("other.test/team/api@{OLD}"), declared),
            (
                format!("docker-pullable://docker.io/library/alpine@{OLD}"),
                declared,
            ),
            (
                format!("registry.test:5000/team/api@{OLD}"),
                "registry.test:5000/team/api:old",
            ),
            ("registry.test:5000/team/api@sha256:short".into(), declared),
        ] {
            let pod = json!({"items":[{
                "metadata":{"name":"test"},
                "spec":{"ephemeralContainers":[{"name":"debug","image":declared}]},
                "status":{"ephemeralContainerStatuses":[{"name":"debug","image":status_image,"imageID":id}]}
            }]});
            let images = pod_images(&pod, &[]);
            assert_eq!(images[0].reference, declared);
            let usage = images[0].usages.first().unwrap();
            assert_eq!(usage.container_type, "ephemeral");
            assert!(!usage.runtime_digest, "{id}");
        }
        assert_eq!(
            runtime_reference(
                "alpine:3",
                &json!({
                    "image":"index.docker.io/library/alpine:3",
                    "imageID":format!("docker-pullable://registry-1.docker.io/library/alpine@{OLD}")
                })
            ),
            Some(format!("docker.io/library/alpine@{OLD}"))
        );
    }

    #[test]
    fn docker_matches_running_containers_by_image_id() {
        let images = docker_images(
            &[
                json!({"Id":OLD,"RepoTags":["api:stable"]}),
                json!({"Id":NEW,"RepoTags":["api:old"]}),
            ],
            Some(&[
                json!({"ImageID":OLD,"Image":"api:old","State":"running"}),
                json!({"ImageID":NEW,"Image":"api:old","State":"exited"}),
            ]),
        );
        assert_eq!(images[0]["running"], true);
        assert_eq!(images[1]["running"], false);
        assert_eq!(
            docker_images(&[json!({"Id":OLD})], None)[0]["running"],
            Value::Null
        );
    }

    #[test]
    fn swarm_exposes_only_valid_manifest_digests_for_bulk_selection() {
        let service = |name: &str, reference: &str| {
            json!({
                "Spec":{"Name":name,"TaskTemplate":{"ContainerSpec":{"Image":reference}}}
            })
        };
        let pinned = format!("registry.test/team/api:stable@{OLD}");
        let alias = format!("other.test/copy@{OLD}");
        let items = swarm_images(&[
            service("api", &pinned),
            service("copy", &alias),
            service("tag", "registry.test/team/api:stable"),
            service("invalid", "registry.test/team/api@sha256:short"),
        ]);
        assert_eq!(items[0]["reference"], pinned);
        assert_eq!(items[0]["registryHost"], "registry.test");
        assert_eq!(items[0]["digest"], OLD);
        assert_eq!(items[1]["digest"], OLD);
        assert_eq!(items[2]["digest"], Value::Null);
        assert_eq!(items[3]["digest"], Value::Null);
    }
}
