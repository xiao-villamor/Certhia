use anyhow::{Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use url::Url;

static REPOSITORY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$",
    )
    .unwrap()
});
static TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$").unwrap());
static DIGEST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^sha256:[a-f0-9]{64}$").unwrap());
static HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?::[0-9]{1,5})?$").unwrap()
});

pub const PLATFORMS: [&str; 3] = ["linux/amd64", "linux/arm64", "linux/arm/v7"];

pub fn registry_host(value: &str) -> Result<String> {
    let value = value
        .trim()
        .strip_prefix("https://")
        .unwrap_or(value.trim())
        .trim_end_matches('/');
    if value.len() > 259 || !HOST.is_match(value) {
        bail!("Enter a registry hostname with an optional port.");
    }
    let url = Url::parse(&format!("https://{value}"))
        .map_err(|_| anyhow::anyhow!("Enter a valid registry hostname and port."))?;
    let host = url.host_str().unwrap_or_default();
    if host.is_empty() || url.port() == Some(0) || host.split('.').any(|label| label.is_empty()) {
        bail!("Enter a valid registry hostname and port.");
    }
    if host != "localhost" && !host.contains(['.', ':']) && url.port().is_none() {
        bail!("Use a fully qualified registry hostname or include a port.");
    }
    let host = match host {
        "registry-1.docker.io" | "index.docker.io" => "docker.io",
        host => host,
    };
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

#[derive(Debug, PartialEq)]
pub struct ImageReference {
    pub host: String,
    pub value: String,
}

impl ImageReference {
    pub fn parse(value: &str, registry: Option<&str>) -> Result<Self> {
        let value = value.trim();
        let value = value.strip_prefix("https://").unwrap_or(value);
        if value.is_empty() || value.len() > 1024 {
            bail!("Enter an image reference up to 1024 characters.");
        }
        let (host, rest) = match value.split_once('/') {
            Some((prefix, rest))
                if prefix.contains(['.', ':']) || prefix.eq_ignore_ascii_case("localhost") =>
            {
                (registry_host(prefix)?, rest)
            }
            _ => (registry.unwrap_or("docker.io").to_owned(), value),
        };
        if registry.is_some_and(|saved| saved != host) {
            bail!("The image host and port must match the selected registry.");
        }

        let (name_and_tag, digest) = match rest.split_once('@') {
            Some((name, digest)) if DIGEST.is_match(digest) => (name, Some(digest)),
            Some(_) => bail!("Enter a valid sha256 manifest digest."),
            None => (rest, None),
        };
        let (name, tag) = match name_and_tag.rsplit_once(':') {
            Some((name, tag)) if TAG.is_match(tag) => (name, Some(tag)),
            Some(_) => bail!("Enter a valid image tag."),
            None => (name_and_tag, None),
        };
        if !REPOSITORY.is_match(name) {
            bail!("Enter a valid repository path.");
        }
        let name = if host == "docker.io" && !name.contains('/') {
            format!("library/{name}")
        } else {
            name.to_owned()
        };
        let value = match digest {
            Some(digest) => format!("{host}/{name}@{digest}"),
            None => format!("{host}/{name}:{}", tag.unwrap_or("latest")),
        };
        Ok(Self { host, value })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct Package {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer_index: Option<i32>,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    pub id: String,
    pub ecosystem: String,
    pub package: String,
    pub installed: String,
    pub fixed: String,
    pub severity: String,
    pub title: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unknown: usize,
    pub packages: usize,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub packages: Vec<Package>,
    pub findings: Vec<Finding>,
    pub inventory_available: bool,
    pub digest: Option<String>,
    pub counts: Counts,
    #[serde(default)]
    pub checks: Vec<Check>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub os: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub struct Check {
    pub category: String,
    pub id: String,
    pub target: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
}

#[derive(Default)]
pub struct Captured {
    pub report: Report,
    pub raw: Option<Vec<u8>>,
    pub scanner: Option<String>,
    pub partial: bool,
    pub scanner_version: Option<String>,
    pub scanner_db_version: Option<String>,
    pub advisory_metadata: serde_json::Value,
    pub artifacts: Vec<(String, Vec<u8>)>,
}

impl Captured {
    pub fn from_trivy(bytes: &[u8]) -> Result<Self> {
        let mut raw: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("Upload a valid Trivy container image JSON report."))?;
        if let Some(results) = raw
            .get_mut("Results")
            .and_then(serde_json::Value::as_array_mut)
        {
            for result in results {
                if let Some(secrets) = result
                    .get_mut("Secrets")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for finding in secrets {
                        if let Some(finding) = finding.as_object_mut() {
                            finding.remove("Match");
                            finding.remove("Code");
                        }
                    }
                }
            }
        }
        let mut advisories = std::collections::BTreeMap::new();
        for result in raw["Results"].as_array().into_iter().flatten() {
            for finding in result["Vulnerabilities"].as_array().into_iter().flatten() {
                if let Some(id) = finding["VulnerabilityID"].as_str() {
                    let cvss = finding["CVSS"]
                        .as_object()
                        .and_then(|v| v.get("nvd").or_else(|| v.values().next()));
                    let timestamp = |key: &str| {
                        finding[key]
                            .as_str()
                            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
                    };
                    let meta = serde_json::json!({"id":id,"description":finding["Description"].as_str(),"refs":finding["References"].as_array(),
                        "published_at":timestamp("PublishedDate"),"modified_at":timestamp("LastModifiedDate"),
                        "cvss_score":cvss.and_then(|v|v["V3Score"].as_f64()),"cvss_vector":cvss.and_then(|v|v["V3Vector"].as_str()),
                        "epss":finding["EPSS"].as_f64(),"kev":finding["KEV"].as_bool()});
                    if meta
                        .as_object()
                        .is_some_and(|v| v.iter().any(|(k, v)| k != "id" && !v.is_null()))
                    {
                        advisories.insert(id.to_owned(), meta);
                    }
                }
            }
        }
        let advisory_metadata = serde_json::to_value(advisories.into_values().collect::<Vec<_>>())?;
        let scanner_version = raw["Trivy"]["Version"].as_str().map(str::to_owned);
        let scanner_db_version = raw["Trivy"]["VulnerabilityDB"]["UpdatedAt"]
            .as_str()
            .map(str::to_owned);
        let raw = serde_json::to_vec(&raw)?;
        let report = Report::from_trivy(&raw)?;
        Ok(Self {
            report,
            raw: Some(raw),
            scanner: Some("trivy".into()),
            artifacts: Vec::new(),
            partial: false,
            scanner_version,
            scanner_db_version,
            advisory_metadata,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyReport {
    schema_version: u32,
    artifact_type: String,
    #[serde(default)]
    results: Option<Vec<TrivyResult>>,
    #[serde(default)]
    metadata: TrivyMetadata,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyMetadata {
    #[serde(default)]
    repo_digests: Option<Vec<String>>,
    #[serde(default, rename = "DiffIDs")]
    diff_ids: Option<Vec<String>>,
    size: Option<u64>,
    os: Option<TrivyOs>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyResult {
    #[serde(default)]
    target: String,
    #[serde(default)]
    class: String,
    #[serde(rename = "Type")]
    #[serde(default)]
    ecosystem: String,
    packages: Option<Vec<TrivyPackage>>,
    vulnerabilities: Option<Vec<TrivyFinding>>,
    misconfigurations: Option<Vec<TrivyCheck>>,
    secrets: Option<Vec<TrivyCheck>>,
    licenses: Option<Vec<TrivyCheck>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyOs {
    family: String,
    name: String,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "PascalCase")]
struct TrivyCheck {
    #[serde(rename = "ID", alias = "RuleID")]
    id: String,
    name: String,
    title: String,
    severity: String,
    message: String,
    resolution: String,
    #[serde(rename = "PkgName")]
    pkg_name: String,
    status: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyPackage {
    identifier: Option<PackageIdentifier>,
    layer: Option<PackageLayer>,
    name: String,
    version: String,
}

#[derive(Deserialize)]
struct PackageIdentifier {
    #[serde(rename = "PURL")]
    purl: Option<String>,
}
#[derive(Deserialize)]
struct PackageLayer {
    #[serde(rename = "DiffID")]
    diff_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct TrivyFinding {
    pkg_identifier: Option<PackageIdentifier>,
    #[serde(rename = "VulnerabilityID")]
    id: String,
    pkg_name: String,
    installed_version: String,
    #[serde(default)]
    fixed_version: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    title: String,
}

impl Report {
    pub fn from_trivy(bytes: &[u8]) -> Result<Self> {
        let input: TrivyReport = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("Upload a valid Trivy container image JSON report."))?;
        if input.schema_version != 2 || input.artifact_type != "container_image" {
            bail!("Upload a Trivy container image report with schema version 2.");
        }
        let layers: BTreeMap<_, _> = input
            .metadata
            .diff_ids
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(i, id)| (id.as_str(), i as i32))
            .collect();
        let mut inventory_available = false;
        let mut packages = BTreeSet::new();
        let mut findings = BTreeSet::new();
        let mut checks = BTreeSet::new();
        for result in input.results.unwrap_or_default() {
            inventory_available |= result.packages.is_some();
            let ecosystem = if result.ecosystem.is_empty() && result.class == "os-pkgs" {
                result.class
            } else {
                result.ecosystem
            };
            for pkg in result.packages.unwrap_or_default() {
                packages.insert(Package {
                    purl: pkg.identifier.and_then(|v| v.purl),
                    layer_index: pkg
                        .layer
                        .and_then(|l| l.diff_id)
                        .and_then(|l| layers.get(l.as_str()).copied()),
                    ecosystem: ecosystem.clone(),
                    name: pkg.name,
                    version: pkg.version,
                });
            }
            for finding in result.vulnerabilities.unwrap_or_default() {
                findings.insert(Finding {
                    purl: finding.pkg_identifier.and_then(|v| v.purl),
                    id: finding.id,
                    ecosystem: ecosystem.clone(),
                    package: finding.pkg_name,
                    installed: finding.installed_version,
                    fixed: finding.fixed_version,
                    severity: match finding.severity.as_str() {
                        severity @ ("CRITICAL" | "HIGH" | "MEDIUM" | "LOW") => severity.to_owned(),
                        _ => "UNKNOWN".to_owned(),
                    },
                    title: finding.title,
                });
            }
            for (category, values) in [
                ("configuration", result.misconfigurations),
                ("secret", result.secrets),
                ("license", result.licenses),
            ] {
                for check in values.unwrap_or_default() {
                    if check.status.eq_ignore_ascii_case("PASS") {
                        continue;
                    }
                    let title = if !check.title.is_empty() {
                        check.title
                    } else if !check.name.is_empty() {
                        check.name.clone()
                    } else {
                        check.id.clone()
                    };
                    let detail = if category == "secret" {
                        String::new()
                    } else if !check.resolution.is_empty() {
                        check.resolution
                    } else {
                        check.message
                    };
                    let id = if !check.id.is_empty() {
                        check.id
                    } else if !check.pkg_name.is_empty() {
                        check.pkg_name
                    } else {
                        check.name
                    };
                    checks.insert(Check {
                        category: category.to_owned(),
                        id,
                        title,
                        detail,
                        target: result.target.clone(),
                        severity: check.severity,
                    });
                }
            }
        }
        let digest = input
            .metadata
            .repo_digests
            .unwrap_or_default()
            .iter()
            .find_map(|reference| {
                reference
                    .rsplit_once('@')
                    .filter(|(_, digest)| DIGEST.is_match(digest))
                    .map(|(_, digest)| digest.to_owned())
            });
        let mut report = Self {
            packages: packages.into_iter().collect(),
            findings: findings.into_iter().collect(),
            inventory_available,
            digest,
            counts: Counts::default(),
            checks: checks.into_iter().collect(),
            size_bytes: input.metadata.size,
            os: input
                .metadata
                .os
                .map(|os| format!("{} {}", os.family, os.name)),
        };
        report.recount();
        Ok(report)
    }

    pub fn recount(&mut self) {
        let mut counts = Counts {
            packages: self.packages.len(),
            ..Counts::default()
        };
        for finding in &self.findings {
            match finding.severity.as_str() {
                "CRITICAL" => counts.critical += 1,
                "HIGH" => counts.high += 1,
                "MEDIUM" => counts.medium += 1,
                "LOW" => counts.low += 1,
                _ => counts.unknown += 1,
            }
        }
        self.counts = counts;
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub name: String,
    pub ecosystem: String,
    pub status: &'static str,
    pub before: Vec<String>,
    pub after: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    pub packages: Vec<Change>,
    pub findings: Vec<Change>,
    pub inventory_available: bool,
}

type Versions = BTreeMap<(String, String), BTreeSet<String>>;

fn diff(before: Versions, after: Versions) -> Vec<Change> {
    let keys: BTreeSet<_> = before.keys().chain(after.keys()).collect();
    keys.into_iter()
        .filter_map(|key| {
            let previous = before.get(key);
            let current = after.get(key);
            if previous == current {
                return None;
            }
            let status = match (previous, current) {
                (None, _) => "Added",
                (_, None) => "Removed",
                _ => "Changed",
            };
            Some(Change {
                ecosystem: key.0.clone(),
                name: key.1.clone(),
                status,
                before: previous.into_iter().flatten().cloned().collect(),
                after: current.into_iter().flatten().cloned().collect(),
            })
        })
        .collect()
}

fn packages(report: &Report) -> Versions {
    let mut versions = Versions::new();
    for package in &report.packages {
        versions
            .entry((package.ecosystem.clone(), package.name.clone()))
            .or_default()
            .insert(package.version.clone());
    }
    versions
}

fn findings(report: &Report) -> Versions {
    let mut versions = Versions::new();
    for finding in &report.findings {
        let label = format!("{} · {}", finding.id, finding.package);
        let mut state = format!("{} · {}", finding.severity, finding.installed);
        if !finding.fixed.is_empty() {
            state.push_str(&format!(" → {}", finding.fixed));
        }
        versions
            .entry((finding.ecosystem.clone(), label))
            .or_default()
            .insert(state);
    }
    versions
}

pub fn compare(baseline: &Report, target: &Report) -> Comparison {
    let inventory_available = baseline.inventory_available && target.inventory_available;
    Comparison {
        inventory_available,
        packages: if inventory_available {
            diff(packages(baseline), packages(target))
        } else {
            Vec::new()
        },
        findings: diff(findings(baseline), findings(target)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn image_reference_preserves_nested_paths_and_validates_saved_host() -> Result<()> {
        let example = "registry.example.test/dist/qa/container-platform:9.5.3";
        assert_eq!(ImageReference::parse(example, None)?.value, example);
        assert_eq!(
            ImageReference::parse("alpine", None)?.value,
            "docker.io/library/alpine:latest"
        );
        assert_eq!(
            ImageReference::parse("dist/qa/app:1", Some("registry.example:5000"))?.value,
            "registry.example:5000/dist/qa/app:1"
        );
        assert!(ImageReference::parse("other.example/app:1", Some("registry.example")).is_err());
        assert!(ImageReference::parse("registry.example/app;bad", None).is_err());
        assert!(ImageReference::parse("registry.example/app@sha256:bad", None).is_err());
        Ok(())
    }

    fn sample(version: &str, with_findings: bool) -> Report {
        let findings = if with_findings {
            vec![json!({
                "VulnerabilityID": "TEST-1", "PkgName": "openssl", "InstalledVersion": version,
                "Severity": "HIGH", "FixedVersion": "3"
            })]
        } else {
            Vec::new()
        };
        Report::from_trivy(&serde_json::to_vec(&json!({
            "SchemaVersion": 2, "ArtifactType": "container_image",
            "Results": [{ "Type": "alpine", "Packages": [{"Name": "openssl", "Version": version}], "Vulnerabilities": findings }]
        })).unwrap()).unwrap()
    }

    #[test]
    fn comparison_reports_version_changes_and_findings_missing_from_target() {
        let baseline = sample("2", true);
        let target = sample("3", false);
        let result = compare(&baseline, &target);
        assert_eq!(baseline.counts.high, 1);
        assert_eq!(result.packages[0].before, vec!["2"]);
        assert_eq!(result.packages[0].after, vec!["3"]);
        assert_eq!(result.findings[0].status, "Removed");
    }

    #[test]
    fn missing_inventory_avoids_false_package_removals() {
        let target =
            Report::from_trivy(br#"{"SchemaVersion":2,"ArtifactType":"container_image"}"#).unwrap();
        let result = compare(&sample("2", false), &target);
        assert!(!result.inventory_available);
        assert!(result.packages.is_empty());
    }
}
