use crate::{ApiError, ApiResult, App, scanner::MAX_REPORT_BYTES};
use anyhow::{Result, anyhow};
use axum::{
    Json, Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::StreamExt;
use reqwest::Client;

use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Duration};

pub const TOOLS: &[&str] = &["trivy", "grype", "syft", "dockle", "dive", "osv"];

pub const FINDING_SOURCES: &str = "finding-sources";

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct Detection {
    #[serde(default)]
    pub aliases: Option<Vec<String>>,
    pub id: String,
    pub ecosystem: String,
    pub package: String,
    pub installed: String,
    pub scanner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

pub fn record_trivy(captured: &mut crate::domain::Captured) {
    // A native Trivy run retains its actual report as the evidence.
    captured
        .artifacts
        .push((FINDING_SOURCES.into(), b"null".to_vec()));
}

impl Detection {
    pub fn new(finding: &crate::domain::Finding, scanner: &str) -> Self {
        Self {
            id: finding.id.clone(),
            aliases: Some(finding.aliases.clone()),
            ecosystem: finding.ecosystem.clone(),
            package: finding.package.clone(),
            installed: finding.installed.clone(),
            scanner: scanner.into(),
            purl: finding.purl.clone(),
        }
    }
}

fn trivy_detections(report: &crate::domain::Report) -> BTreeSet<Detection> {
    report
        .findings
        .iter()
        .map(|finding| Detection::new(finding, "trivy"))
        .collect()
}

pub fn routes() -> Router<App> {
    Router::new()
        .route("/scans/{id}/scanner-results", get(list))
        .route("/scans/{id}/finding-sources", get(finding_sources))
        .route("/scans/{id}/scanner-results/{tool}", get(download))
        .route("/config/raw-output", get(config))
}

fn env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub(crate) fn store() -> Option<(Bucket, Credentials)> {
    let name = env("CERTHIA_S3_BUCKET")?;
    let access = env("CERTHIA_S3_ACCESS_KEY")?;
    let secret = env("CERTHIA_S3_SECRET_KEY")?;
    let region = env("CERTHIA_S3_REGION").unwrap_or_else(|| "us-east-1".into());
    let (endpoint, style) = match env("CERTHIA_S3_ENDPOINT") {
        Some(endpoint) => (endpoint, UrlStyle::Path),
        None => (
            format!("https://s3.{region}.amazonaws.com"),
            UrlStyle::VirtualHost,
        ),
    };
    let bucket = Bucket::new(endpoint.parse().ok()?, style, name, region).ok()?;
    Some((bucket, Credentials::new(access, secret)))
}

pub(crate) fn client() -> Result<Client> {
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()?)
}

pub async fn read(key: &str) -> Result<Option<Vec<u8>>> {
    let Some((bucket, credentials)) = store() else {
        return Ok(None);
    };
    let url = bucket
        .get_object(Some(&credentials), key)
        .sign(Duration::from_secs(90));
    let response = client()?
        .get(url)
        .send()
        .await
        .map_err(|_| anyhow!("Could not contact the artifact store."))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    anyhow::ensure!(
        response.status().is_success(),
        "The artifact store rejected the request."
    );
    let mut stream = response.bytes_stream();
    let mut result = Vec::new();
    while let Some(part) = stream.next().await {
        let next = part.map_err(|_| anyhow!("Artifact download was interrupted."))?;
        anyhow::ensure!(
            result.len() + next.len() <= MAX_REPORT_BYTES,
            "The artifact exceeds the report size limit."
        );
        result.extend_from_slice(&next);
    }
    Ok(Some(result))
}

async fn config() -> Json<Value> {
    Json(json!({"objectStorage":store().is_some(),"rawReports":true}))
}

async fn list(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    if app.0.database.replay(&id).await?.is_none() {
        return Err(ApiError::missing("Scan not found."));
    }
    let kinds=sqlx::query_scalar!(r#"SELECT kind AS "kind!" FROM artifact_refs WHERE scan_id=$1 UNION SELECT 'trivy' FROM scans s JOIN scan_directory d USING(id,queued_at) WHERE d.id=$1 AND s.raw_report_ref IS NOT NULL ORDER BY 1"#,crate::key(&id)?).fetch_all(&app.0.database.primary).await?;
    Ok(Json(
        json!({"scanners":kinds.into_iter().filter(|kind| kind != FINDING_SOURCES && kind != "discrepancies" && kind != crate::discrepancies::ARTIFACT).collect::<Vec<_>>()}),
    ))
}

async fn finding_sources(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<Detection>>> {
    let job = app
        .0
        .database
        .replay(&id)
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    Ok(Json(detections(&app, &id, &job.source).await?))
}

pub(crate) async fn detections(app: &App, id: &str, source: &str) -> Result<Vec<Detection>> {
    let stored = report(app, id, FINDING_SOURCES).await?;
    if let Some(bytes) = &stored
        && let Some(mut rows) = serde_json::from_slice::<Option<Vec<Detection>>>(bytes)?
    {
        // Older evidence files contain detector identities but no alias field. Read their retained originals.
        let legacy: BTreeSet<_> = rows
            .iter()
            .filter(|r| r.aliases.is_none())
            .map(|r| r.scanner.clone())
            .collect();
        for tool in legacy {
            let original = if tool == "trivy" {
                trivy(app, id).await
            } else {
                report(app, id, &tool).await
            };
            let Ok(Some(raw)) = original else {
                continue;
            };
            let parsed = tokio::task::spawn_blocking(move || -> Result<_> {
                let report = match tool.as_str() {
                    "trivy" => crate::domain::Report::from_trivy(&raw)?,
                    "grype" | "osv" => crate::native_scanners::parse(
                        &tool,
                        &mut serde_json::from_slice(&raw)?,
                        "",
                    )?,
                    _ => return Ok(Vec::new()),
                };
                Ok(report
                    .findings
                    .iter()
                    .map(|f| Detection::new(f, &tool))
                    .collect::<Vec<_>>())
            })
            .await?;
            if let Ok(parsed) = parsed {
                rows.extend(parsed);
            }
        }
        return Ok(rows);
    }
    if (stored.is_some() || source == "import")
        && let Some(bytes) = trivy(app, id).await?
    {
        return tokio::task::spawn_blocking(move || {
            let report = crate::domain::Report::from_trivy(&bytes)?;
            Ok(trivy_detections(&report).into_iter().collect())
        })
        .await?;
    }
    Ok(Vec::new())
}

pub async fn enrich(
    app: &App,
    id: &str,
    source: &str,
    result: &mut crate::domain::Report,
) -> Result<()> {
    if result.findings.is_empty() {
        return Ok(());
    }
    let rows = detections(app, id, source).await?;
    let mut by_package = std::collections::BTreeMap::<_, Vec<&Detection>>::new();
    for row in &rows {
        for id in std::iter::once(&row.id).chain(row.aliases.iter().flatten()) {
            by_package
                .entry((
                    id.as_str(),
                    row.package.as_str(),
                    row.ecosystem.as_str(),
                    row.installed.as_str(),
                    row.purl.as_deref(),
                ))
                .or_default()
                .push(row);
        }
    }
    for finding in &mut result.findings {
        let key = (
            finding.id.as_str(),
            finding.package.as_str(),
            finding.ecosystem.as_str(),
            finding.installed.as_str(),
            finding.purl.as_deref(),
        );
        if let Some(matches) = by_package.get(&key) {
            let mut ids = BTreeSet::new();
            let mut engines = BTreeSet::new();
            let owners: BTreeSet<_> = matches
                .iter()
                .filter(|r| r.id != finding.id)
                .map(|r| &r.id)
                .collect();
            for row in matches {
                if owners.len() > 1 && row.id != finding.id {
                    continue;
                }
                ids.insert(row.id.clone());
                ids.extend(row.aliases.iter().flatten().cloned());
                engines.insert(row.scanner.clone());
            }
            ids.remove(&finding.id);
            finding.aliases = ids.into_iter().collect();
            finding.detected_by = engines.into_iter().collect();
        }
    }
    Ok(())
}

pub async fn cbom(app: &App, id: &str) -> Result<Option<Vec<u8>>> {
    for kind in ["cbom", "sbom"] {
        if let Some(bytes) = report(app, id, kind).await?
            && let Some(bytes) =
                tokio::task::spawn_blocking(move || has_crypto_inventory(&bytes).then_some(bytes))
                    .await?
        {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn has_crypto_inventory(bytes: &[u8]) -> bool {
    let Ok(bom) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    if bom["bomFormat"] != "CycloneDX" {
        return false;
    }
    let mut components: Vec<_> = bom["components"].as_array().into_iter().flatten().collect();
    if let Some(component) = bom["metadata"].get("component") {
        components.push(component);
    }
    while let Some(component) = components.pop() {
        if component["type"] == "cryptographic-asset"
            && component["cryptoProperties"]["assetType"].is_string()
        {
            return true;
        }
        components.extend(component["components"].as_array().into_iter().flatten());
    }
    false
}
pub async fn trivy(app: &App, id: &str) -> Result<Option<Vec<u8>>> {
    if let Some(bytes) = report(app, id, "trivy").await? {
        return Ok(crate::domain::Captured::from_trivy(&bytes)?.raw);
    }
    let key = sqlx::query_scalar!(
        "SELECT raw_report_ref FROM scans JOIN scan_directory USING(id,queued_at) WHERE id=$1",
        uuid::Uuid::parse_str(id)?
    )
    .fetch_optional(&app.0.database.primary)
    .await?
    .flatten();
    match key {
        Some(key) => crate::artifact_blob::retrieve(&app.0.data, &key).await,
        None => Ok(None),
    }
}
pub(crate) async fn report(app: &App, id: &str, kind: &str) -> Result<Option<Vec<u8>>> {
    let row = sqlx::query!(
        "SELECT object_key,owned FROM artifact_refs WHERE scan_id=$1 AND kind=$2",
        uuid::Uuid::parse_str(id)?,
        kind
    )
    .fetch_optional(&app.0.database.primary)
    .await?;
    match row {
        Some(r) if r.owned => crate::artifact_blob::retrieve(&app.0.data, &r.object_key).await,
        Some(r) => read(&r.object_key).await,
        None => Ok(None),
    }
}

pub async fn discrepancies(app: &App, id: &str) -> Result<Option<Vec<u8>>> {
    use crate::discrepancies::{ARTIFACT, from_bytes};
    if let Some(bytes) = report(app, id, ARTIFACT).await? {
        return Ok(Some(bytes));
    }
    let (trivy, grype, osv) = tokio::try_join!(
        trivy(app, id),
        report(app, id, "grype"),
        report(app, id, "osv")
    )?;
    let reports = [trivy, grype, osv];
    if reports.iter().flatten().count() < 2 {
        return Ok(None);
    }
    let sbom = report(app, id, "sbom").await?;
    tokio::task::spawn_blocking(move || {
        from_bytes(
            reports.each_ref().map(|raw| raw.as_deref()),
            sbom.as_deref(),
        )
        .map(Some)
    })
    .await?
}

pub async fn bundle(app: &App, id: &str) -> Result<Vec<(String, Vec<u8>)>> {
    const MAX_BUNDLE_INPUT: usize = 80 * 1024 * 1024;
    let mut files = Vec::new();
    let mut bytes = 0;
    if let Some(raw) = trivy(app, id).await? {
        bytes += raw.len();
        files.push(("trivy.json".into(), raw));
    }
    for kind in TOOLS.iter().filter(|&&tool| tool != "trivy") {
        if let Ok(Some(report)) = report(app, id, kind).await
            && bytes + report.len() <= MAX_BUNDLE_INPUT
        {
            bytes += report.len();
            files.push((format!("{kind}.json"), report));
        }
    }
    Ok(files)
}

async fn download(
    State(app): State<App>,
    Path((id, tool)): Path<(String, String)>,
) -> ApiResult<Response> {
    if !TOOLS.contains(&tool.as_str())
        && !matches!(
            tool.as_str(),
            "sbom" | "cbom" | crate::exports::SCHEDULED_SBOM
        )
    {
        return Err(ApiError::missing("Unknown scanner."));
    }
    let scan = app
        .0
        .database
        .replay(&id)
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    let filename = crate::exports::scan_filename(&scan.reference, &scan.platform, &id);
    let bytes = if tool == "trivy" {
        trivy(&app, &id).await?
    } else {
        report(&app, &id, &tool).await?
    }
    .ok_or_else(|| ApiError::missing("Scanner report unavailable."))?;
    if tool == crate::exports::SCHEDULED_SBOM {
        return Ok(crate::exports::attachment(
            &filename,
            "application/vnd.cyclonedx+json",
            "cdx.json",
            bytes,
        ));
    }
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/json".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}.{tool}.json\""),
            ),
        ],
        bytes,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbom_requires_cryptographic_evidence() {
        assert!(!has_crypto_inventory(
            br#"{"bomFormat":"CycloneDX","components":[{"type":"library","name":"openssl"}]}"#
        ));
        assert!(!has_crypto_inventory(br#"{"components":[{"type":"cryptographic-asset","cryptoProperties":{"assetType":"algorithm"}}]}"#));
        assert!(has_crypto_inventory(br#"{"bomFormat":"CycloneDX","components":[{"type":"application","components":[{"type":"cryptographic-asset","cryptoProperties":{"assetType":"algorithm"}}]}]}"#));
    }
}
