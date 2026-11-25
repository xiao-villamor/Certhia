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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    pub id: String,
    #[serde(default)]
    #[sqlx(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    #[sqlx(default)]
    pub detected_by: Vec<String>,
    pub ecosystem: String,
    pub package: String,
    pub installed: String,
    pub fixed: String,
    pub severity: String,
    pub title: String,
}

static ADVISORY_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:CVE-[0-9]{4}-[0-9]{4,}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})$").unwrap()
});

/// Only structured scanner identifiers can establish a cross-database advisory identity.
pub fn advisory_identity<'a>(
    primary: &str,
    aliases: impl IntoIterator<Item = &'a str>,
) -> (String, Vec<String>) {
    let mut ids: BTreeSet<String> = aliases
        .into_iter()
        .filter(|id| ADVISORY_ID.is_match(id))
        .map(str::to_owned)
        .collect();
    ids.remove(primary);
    let mut cves = ids.iter().filter(|id| id.starts_with("CVE-"));
    let cve = cves.next().cloned();
    if cve.is_some() && (cves.next().is_some() || primary.starts_with("CVE-")) {
        return (primary.to_owned(), Vec::new());
    }
    if let Some(cve) = cve {
        ids.remove(&cve);
        ids.insert(primary.to_owned());
        return (cve, ids.into_iter().collect());
    }
    (primary.to_owned(), ids.into_iter().collect())
}

impl Finding {
    pub fn record_aliases<'a>(&mut self, ids: impl IntoIterator<Item = &'a str>) {
        (self.id, self.aliases) = advisory_identity(&self.id, ids);
    }
}

pub fn merge_findings(rows: impl Iterator<Item = Finding>) -> Vec<Finding> {
    let mut findings: BTreeMap<_, Finding> = BTreeMap::new();
    for finding in rows {
        let key = (
            finding.id.clone(),
            finding.ecosystem.clone(),
            finding.package.clone(),
            finding.installed.clone(),
            finding.purl.clone(),
        );
        let existing = findings.entry(key).or_insert_with(|| finding.clone());
        existing.aliases.extend(finding.aliases);
        existing.aliases.sort();
        existing.aliases.dedup();
        if severity_rank(&finding.severity) > severity_rank(&existing.severity) {
            existing.severity = finding.severity;
        }
        if existing.title.is_empty() {
            existing.title = finding.title;
        }
        if existing.fixed.is_empty() {
            existing.fixed = finding.fixed;
        }
    }
    findings.into_values().collect()
}

pub fn severity_rank(severity: &str) -> u8 {
    match severity {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

pub fn scanner_names(ids: &[String]) -> String {
    ids.iter()
        .map(|id| match id.as_str() {
            "trivy" => "Trivy",
            "grype" => "Grype",
            "syft" => "Syft",
            "osv" => "OSV-Scanner",
            "dockle" => "Dockle",
            "dive" => "Dive",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(", ")
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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_available: Option<bool>,
    #[serde(default)]
    pub scanners: Vec<String>,
    pub packages: Vec<Package>,
    pub findings: Vec<Finding>,
    pub inventory_available: bool,
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_complete: Option<bool>,
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
                    let (id, _) = advisory_identity(
                        id,
                        finding["VendorIDs"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|v| v.as_str()),
                    );
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
                        advisories.insert(id, meta);
                    }
                }
            }
        }
        let advisory_metadata = serde_json::Value::Array(advisories.into_values().collect());
        let scanner_version = raw["Trivy"]["Version"].as_str().map(str::to_owned);
        let scanner_db_version = raw["Trivy"]["VulnerabilityDB"]["UpdatedAt"]
            .as_str()
            .map(str::to_owned);
        let input = TrivyReport::deserialize(&raw)
            .map_err(|_| anyhow::anyhow!("Upload a valid Trivy container image JSON report."))?;
        let (report, _) = Report::normalize_trivy(input)?;
        let raw = serde_json::to_vec(&raw)?;
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
    #[serde(rename = "OS", alias = "Os")]
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
    family: Option<String>,
    name: Option<String>,
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
    #[serde(default, rename = "VendorIDs")]
    vendor_ids: Option<Vec<String>>,
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
        Self::parse_trivy(bytes).map(|(report, _)| report)
    }

    pub(crate) fn parse_trivy(bytes: &[u8]) -> Result<(Self, bool)> {
        let input: TrivyReport = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("Upload a valid Trivy container image JSON report."))?;
        Self::normalize_trivy(input)
    }

    fn normalize_trivy(input: TrivyReport) -> Result<(Self, bool)> {
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
        let mut vulnerability_results = false;
        let mut os_vulnerability_results = false;
        let mut packages = BTreeSet::new();
        let mut findings = Vec::new();
        let mut checks = BTreeSet::new();
        for result in input.results.unwrap_or_default() {
            inventory_available |= result.packages.is_some();
            let has_vulnerability_evidence = result.vulnerabilities.is_some()
                || (matches!(result.class.as_str(), "os-pkgs" | "lang-pkgs")
                    && result
                        .packages
                        .as_ref()
                        .is_some_and(|packages| !packages.is_empty()));
            vulnerability_results |= has_vulnerability_evidence;
            os_vulnerability_results |= result.class == "os-pkgs" && has_vulnerability_evidence;
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
                let mut normalized = Finding {
                    aliases: Vec::new(),
                    detected_by: Vec::new(),
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
                };
                normalized.record_aliases(finding.vendor_ids.iter().flatten().map(String::as_str));
                findings.push(normalized);
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
            findings: merge_findings(findings.into_iter()),
            evidence_available: None,
            scanners: vec!["trivy".into()],
            inventory_available,
            digest,
            observation_complete: Some(vulnerability_results),
            counts: Counts::default(),
            checks: checks.into_iter().collect(),
            size_bytes: input.metadata.size,
            os: input.metadata.os.and_then(|os| {
                let (family, name) = (os.family?, os.name?);
                (!family.trim().is_empty() && !name.trim().is_empty())
                    .then(|| format!("{} {}", family.trim(), name.trim()))
            }),
        };
        report.recount();
        Ok((report, os_vulnerability_results))
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
    pub observations: Vec<Observation>,
    pub inventory_available: bool,
}

// Both maps already have ordered keys. Walk them once and move each value
// directly into its comparison row when needed.
fn ordered_pairs<K: Ord, V>(
    before: BTreeMap<K, V>,
    after: BTreeMap<K, V>,
) -> impl Iterator<Item = (K, Option<V>, Option<V>)> {
    let mut before = before.into_iter().peekable();
    let mut after = after.into_iter().peekable();
    std::iter::from_fn(move || {
        use std::cmp::Ordering::{Equal, Greater, Less};
        let order = match (before.peek(), after.peek()) {
            (Some((left, _)), Some((right, _))) => left.cmp(right),
            (Some(_), None) => Less,
            (None, Some(_)) => Greater,
            (None, None) => return None,
        };
        Some(match order {
            Less => {
                let (key, value) = before.next().unwrap();
                (key, Some(value), None)
            }
            Greater => {
                let (key, value) = after.next().unwrap();
                (key, None, Some(value))
            }
            Equal => {
                let (key, previous) = before.next().unwrap();
                let (_, current) = after.next().unwrap();
                (key, Some(previous), Some(current))
            }
        })
    })
}

type Versions<'a, N, V> = BTreeMap<(&'a str, N), BTreeSet<V>>;

fn diff<N: Ord + Into<String>, V: Ord + Into<String>>(
    before: Versions<'_, N, V>,
    after: Versions<'_, N, V>,
) -> Vec<Change> {
    ordered_pairs(before, after)
        .filter_map(|((ecosystem, name), previous, current)| {
            if previous == current {
                return None;
            }
            let status = match (&previous, &current) {
                (None, _) => "Added",
                (_, None) => "Removed",
                _ => "Changed",
            };
            Some(Change {
                ecosystem: ecosystem.into(),
                name: name.into(),
                status,
                before: previous.into_iter().flatten().map(Into::into).collect(),
                after: current.into_iter().flatten().map(Into::into).collect(),
            })
        })
        .collect()
}

fn packages(report: &Report) -> Versions<'_, &str, &str> {
    let mut versions = Versions::new();
    for package in &report.packages {
        versions
            .entry((package.ecosystem.as_str(), package.name.as_str()))
            .or_default()
            .insert(package.version.as_str());
    }
    versions
}

fn findings(report: &Report) -> Versions<'_, String, String> {
    let mut versions = Versions::new();
    for finding in &report.findings {
        let label = format!("{} · {}", finding.id, finding.package);
        versions
            .entry((finding.ecosystem.as_str(), label))
            .or_default()
            .insert(finding_state(finding));
    }
    versions
}

fn finding_state(finding: &Finding) -> String {
    let mut state = format!("{} · {}", finding.severity, finding.installed);
    if !finding.fixed.is_empty() {
        state.push_str(&format!(" → {}", finding.fixed));
    }
    state
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    advisory: String,
    severity: String,
    fix_available: bool,
    #[serde(flatten)]
    change: Change,
}

#[derive(Default)]
struct ObservedPackage<'a> {
    versions: BTreeSet<String>,
    severity: &'a str,
    fix_available: bool,
}

fn observation_versions(report: &Report) -> BTreeMap<(&str, &str, &str), ObservedPackage<'_>> {
    let mut versions = BTreeMap::<_, ObservedPackage<'_>>::new();
    for finding in &report.findings {
        let observed = versions
            .entry((
                finding.ecosystem.as_str(),
                finding.id.as_str(),
                finding.package.as_str(),
            ))
            .or_default();
        observed.versions.insert(finding_state(finding));
        if observed.severity.is_empty()
            || severity_rank(&finding.severity) > severity_rank(observed.severity)
        {
            observed.severity = &finding.severity;
        }
        observed.fix_available |= !finding.fixed.is_empty();
    }
    versions
}

fn observation_diff(baseline: &Report, target: &Report) -> Vec<Observation> {
    let before = observation_versions(baseline);
    let after = observation_versions(target);
    ordered_pairs(before, after)
        .map(|((ecosystem, advisory, package), previous, current)| {
            let evidence = current
                .as_ref()
                .or(previous.as_ref())
                .expect("observation has a report");
            Observation {
                advisory: advisory.to_owned(),
                severity: evidence.severity.to_owned(),
                fix_available: evidence.fix_available,
                change: Change {
                    name: format!("{advisory} · {package}"),
                    ecosystem: ecosystem.to_owned(),
                    status: match (&previous, &current) {
                        (None, _) => "Added",
                        (_, None) => "Removed",
                        _ => "Still detected",
                    },
                    before: previous
                        .map(|item| item.versions.into_iter().collect())
                        .unwrap_or_default(),
                    after: current
                        .map(|item| item.versions.into_iter().collect())
                        .unwrap_or_default(),
                },
            }
        })
        .collect()
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
        observations: observation_diff(baseline, target),
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
        assert_eq!(result.observations[0].change.status, "Removed");
    }

    #[test]
    fn a_changed_package_version_can_still_report_the_same_advisory() {
        let baseline = sample("2", true);
        let mut target = sample("3", true);
        target.findings[0].fixed.clear();
        let result = compare(&baseline, &target);
        assert_eq!(result.observations[0].advisory, "TEST-1");
        assert_eq!(result.observations[0].change.status, "Still detected");
        assert_ne!(
            result.observations[0].change.before,
            result.observations[0].change.after
        );
    }

    #[test]
    fn trivy_uses_uppercase_os_metadata_and_records_incomplete_observations() -> Result<()> {
        let mut document = json!({
            "SchemaVersion": 2, "ArtifactType": "container_image",
            "Metadata": {"OS": {"Family":"alpine","Name":"3.23.8"}},
            "Results": [{"Class":"config","Type":"dockerfile"}]
        });
        let report = Report::from_trivy(&serde_json::to_vec(&document)?)?;
        assert_eq!(report.os.as_deref(), Some("alpine 3.23.8"));
        assert_eq!(report.observation_complete, Some(false));

        document["Results"] =
            json!([{"Class":"os-pkgs","Packages":[{"Name":"musl","Version":"1.2.5"}]}]);
        let report = Report::from_trivy(&serde_json::to_vec(&document)?)?;
        assert_eq!(report.observation_complete, Some(true));
        assert!(report.findings.is_empty());
        Ok(())
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
