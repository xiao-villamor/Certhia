//! Compare the observations in the completed reports from the vulnerability scanners.
use crate::{
    domain::{advisory_identity, severity_rank},
    native_scanners::{ecosystem, osv_findings},
    scanner::MAX_REPORT_BYTES,
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io::Read,
};

pub const SCANNERS: [&str; 3] = ["trivy", "grype", "osv"];
pub const ARTIFACT: &str = "vulnerability-comparison";
const LABELS: [&str; 3] = ["Trivy", "Grype", "OSV-Scanner"];

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub advisory: String,
    pub id: String,
    pub aliases: Vec<String>,
    pub package: String,
    pub ecosystem: String,
    pub version: String,
    pub purl: String,
    pub source_packages: BTreeSet<String>,
    pub severity: String,
    pub fixes: BTreeSet<String>,
    pub cpe_match: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Difference {
    pub status: &'static str,
    pub reasons: Vec<String>,
    pub trivy: Option<Observation>,
    pub grype: Option<Observation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub osv: Option<Observation>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Explanation {
    pub scanners: Vec<&'static str>,
    pub target: &'static str,
    pub agreed: usize,
    pub auto_resolved: usize,
    pub needs_review: usize,
    pub differences: Vec<Difference>,
}

fn items(v: &Value) -> impl Iterator<Item = &Value> {
    v.as_array().into_iter().flatten()
}
fn string(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_default().to_owned()
}

fn qualifier(purl: &str, name: &str) -> Option<String> {
    let (_, query) = purl.split_once('?')?;
    url::form_urlencoded::parse(query.split('#').next()?.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, val)| val.into_owned())
}

fn fixes<'a>(values: impl Iterator<Item = &'a str>) -> BTreeSet<String> {
    values
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

type Origins = BTreeMap<(String, String), BTreeSet<String>>;
fn add_origin(map: &mut Origins, name: &str, version: &str, origin: &str) {
    if !name.is_empty() && !version.is_empty() && !origin.is_empty() && origin != name {
        map.entry((name.into(), version.into()))
            .or_default()
            .insert(origin.into());
    }
}
fn inventory_origins(trivy: &Value, sbom: Option<&Value>) -> Result<Origins> {
    let mut map = Origins::new();
    for target in items(&trivy["Results"]).filter(|r| r["Type"] == "alpine") {
        for pkg in items(&target["Packages"]) {
            let name = string(pkg, "Name");
            let version = string(pkg, "Version");
            let src_version = string(pkg, "SrcVersion");
            if src_version.is_empty() || src_version == version {
                add_origin(&mut map, &name, &version, &string(pkg, "SrcName"));
            }
        }
    }
    if let Some(sbom) = sbom {
        ensure!(
            sbom["bomFormat"] == "CycloneDX",
            "Expected a CycloneDX inventory."
        );
        let mut pending: Vec<_> = items(&sbom["components"]).collect();
        while let Some(component) = pending.pop() {
            pending.extend(items(&component["components"]));
            let purl = string(component, "purl");
            if !purl.starts_with("pkg:apk/alpine/") {
                continue;
            }
            let name = string(component, "name");
            let version = string(component, "version");
            let property = |key: &str| {
                items(&component["properties"])
                    .find(|p| p["name"] == key)
                    .and_then(|p| p["value"].as_str())
            };
            if property("aquasecurity:trivy:SrcVersion").is_some_and(|v| v != version) {
                continue;
            }
            if let Some(source) = property("aquasecurity:trivy:SrcName") {
                add_origin(&mut map, &name, &version, source);
            }
            if let Some(source) = qualifier(&purl, "upstream") {
                add_origin(&mut map, &name, &version, &source);
            }
        }
    }
    Ok(map)
}

fn trivy_rows(report: &Value, origins: &Origins) -> Result<Vec<Observation>> {
    let mut rows = Vec::new();
    for target in items(&report["Results"]) {
        let ecosystem = ecosystem(target["Type"].as_str().unwrap_or_default(), "");
        for vuln in items(&target["Vulnerabilities"]) {
            let advisory = string(vuln, "VulnerabilityID");
            let package = string(vuln, "PkgName");
            let version = string(vuln, "InstalledVersion");
            ensure!(
                !advisory.is_empty() && !package.is_empty(),
                "Incomplete Trivy vulnerability."
            );
            let (id, aliases) = advisory_identity(
                &advisory,
                items(&vuln["VendorIDs"]).filter_map(Value::as_str),
            );
            let purl = string(&vuln["PkgIdentifier"], "PURL");
            let mut source_packages = BTreeSet::new();
            if ecosystem == "alpine" {
                source_packages.extend(
                    origins
                        .get(&(package.clone(), version.clone()))
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
                source_packages.extend(qualifier(&purl, "upstream"));
            }
            rows.push(Observation {
                advisory,
                id,
                aliases,
                package,
                version,
                ecosystem: ecosystem.clone(),
                purl,
                source_packages,
                severity: vuln["Severity"].as_str().unwrap_or_default().to_uppercase(),
                fixes: fixes(vuln["FixedVersion"].as_str().into_iter()),
                cpe_match: false,
            });
        }
    }
    rows.sort_unstable();
    rows.dedup();
    Ok(rows)
}

fn grype_rows(report: &Value) -> Result<Vec<Observation>> {
    let mut rows = Vec::new();
    let distro = report["distro"]["name"].as_str().unwrap_or_default();
    for entry in items(&report["matches"]) {
        let artifact = &entry["artifact"];
        let vuln = &entry["vulnerability"];
        let advisory = string(vuln, "id");
        let package = string(artifact, "name");
        let version = string(artifact, "version");
        ensure!(
            !advisory.is_empty() && !package.is_empty(),
            "Incomplete Grype match."
        );
        let (id, aliases) = advisory_identity(
            &advisory,
            items(&entry["relatedVulnerabilities"]).filter_map(|v| v["id"].as_str()),
        );
        let eco = ecosystem(artifact["type"].as_str().unwrap_or_default(), distro);
        let purl = string(artifact, "purl");
        let mut source_packages = BTreeSet::new();
        if eco == "alpine" {
            source_packages.extend(qualifier(&purl, "upstream"));
            for src in items(&artifact["upstreams"]) {
                if src["version"]
                    .as_str()
                    .is_none_or(|v| v.is_empty() || v == version)
                    && let Some(name) = src["name"].as_str()
                {
                    source_packages.insert(name.to_owned());
                }
            }
        }
        let cpe_match = items(&entry["matchDetails"]).any(|detail| {
            detail["type"] == "cpe-match"
                || detail["matcher"] == "stock-matcher"
                    && detail["searchedBy"]["cpes"]
                        .as_array()
                        .is_some_and(|v| !v.is_empty())
        });
        rows.push(Observation {
            advisory,
            id,
            aliases,
            package,
            version,
            ecosystem: eco,
            purl,
            source_packages,
            cpe_match,
            severity: vuln["severity"].as_str().unwrap_or_default().to_uppercase(),
            fixes: fixes(items(&vuln["fix"]["versions"]).filter_map(Value::as_str)),
        });
    }
    rows.sort_unstable();
    rows.dedup();
    Ok(rows)
}

fn digest(value: &Value) -> Option<&str> {
    let value = value.as_str()?.rsplit('@').next()?;
    let hex = value.strip_prefix("sha256:")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(value)
}
fn target(trivy: &Value, grype: &Value, same_input: bool) -> Result<&'static str> {
    let t = &trivy["Metadata"];
    let g = &grype["source"]["target"];
    let mut identity = None;
    for (left, right) in [
        (&t["ImageConfig"]["architecture"], &g["architecture"]),
        (&t["ImageConfig"]["os"], &g["os"]),
    ] {
        if let (Some(a), Some(b)) = (left.as_str(), right.as_str()) {
            ensure!(a == b, "Reports identify different platforms.");
        }
    }
    if let (Some(a), Some(b)) = (digest(&t["ImageID"]), digest(&g["imageID"])) {
        ensure!(a == b, "Reports identify different image configurations.");
        identity = Some("matching image ID");
    }
    let manifests: BTreeSet<_> = items(&t["RepoDigests"]).filter_map(digest).collect();
    if !manifests.is_empty()
        && let Some(b) = digest(&g["manifestDigest"])
    {
        ensure!(
            manifests.contains(b),
            "Reports identify different manifest digests."
        );
        identity = Some("matching manifest digest");
    }
    Ok(identity.unwrap_or(if same_input {
        "same input supplied"
    } else {
        "unverified"
    }))
}

fn compatible(a: &Observation, b: &Observation) -> bool {
    if a.version.is_empty() || a.ecosystem == "package" {
        return false;
    }
    if a.package == b.package && a.purl == b.purl {
        return true;
    }
    if ["arch","distro"].iter().any(|q| {
        matches!((qualifier(&a.purl,q),qualifier(&b.purl,q)),(Some(x),Some(y)) if x.trim_start_matches("alpine-") != y.trim_start_matches("alpine-"))
    }) { return false; }
    if a.package == b.package {
        return a.purl.is_empty()
            || b.purl.is_empty()
            || a.purl.split(['?', '#']).next() == b.purl.split(['?', '#']).next();
    }
    a.ecosystem == "alpine"
        && (a.source_packages.len() == 1 && a.source_packages.contains(&b.package)
            || b.source_packages.len() == 1 && b.source_packages.contains(&a.package))
}

fn unpaired(row: &Observation, other: &str, ambiguous: bool) -> Vec<String> {
    let mut reasons = vec![if ambiguous {
        "Multiple candidates match the advisory and package origin.".into()
    } else {
        format!("{other} did not report this advisory for this package.")
    }];
    if row.cpe_match {
        reasons.push(
            "Grype recorded a CPE match. Verify the product identity and applicable version range."
                .into(),
        );
    }
    if !row.source_packages.is_empty() {
        reasons.push(format!(
            "{} is a binary package. Recorded source: {}.",
            row.package,
            row.source_packages
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    reasons
}

#[cfg(test)]
fn compare(
    trivy: &Value,
    grype: &Value,
    sbom: Option<&Value>,
    same_input: bool,
) -> Result<Explanation> {
    compare_reports([Some(trivy), Some(grype), None], sbom, same_input)
}

type Reports<T> = [Option<T>; 3];

pub fn compare_reports(
    reports: Reports<&Value>,
    sbom: Option<&Value>,
    same_input: bool,
) -> Result<Explanation> {
    let [trivy, grype, osv] = reports;
    let engines: Vec<_> = (0..SCANNERS.len())
        .filter(|&i| reports[i].is_some())
        .collect();
    ensure!(
        engines.len() >= 2,
        "Supply reports from at least two vulnerability scanners."
    );
    ensure!(
        trivy.is_none_or(|r| r["SchemaVersion"] == 2
            && r["ArtifactType"].is_string()
            && (r["Results"].is_array() || r["Results"].is_null())),
        "Expected a Trivy JSON scan report."
    );
    ensure!(
        grype.is_none_or(|r| r["matches"].is_array()),
        "Expected a Grype JSON scan report."
    );
    ensure!(
        sbom.is_none() || same_input,
        "Confirm that the supplied SBOM and scanner reports describe the same input with --same-input."
    );

    // OSV-Scanner's container report records a source path without a verified image digest.
    let target = match (trivy, grype, osv) {
        (Some(t), Some(g), None) => target(t, g, same_input)?,
        (Some(t), Some(g), Some(_)) => {
            target(t, g, same_input)?;
            if same_input {
                "same input supplied"
            } else {
                "unverified"
            }
        }
        _ if same_input => "same input supplied",
        _ => "unverified",
    };
    let origins = inventory_origins(trivy.unwrap_or(&Value::Null), sbom)?;
    let rows = [
        trivy
            .map(|r| trivy_rows(r, &origins))
            .transpose()?
            .unwrap_or_default(),
        grype.map(grype_rows).transpose()?.unwrap_or_default(),
        osv.map(osv_rows).transpose()?.unwrap_or_default(),
    ];
    Ok(reconcile(rows, &engines, target))
}

fn osv_rows(report: &Value) -> Result<Vec<Observation>> {
    let mut packages = BTreeMap::<_, Observation>::new();
    for (advisory, finding) in osv_findings(report)? {
        let key = (
            finding.id.clone(),
            finding.ecosystem.clone(),
            finding.package.clone(),
            finding.installed.clone(),
            finding.purl.clone(),
        );
        let row = packages.entry(key).or_insert_with(|| Observation {
            advisory: advisory.clone(),
            id: finding.id,
            aliases: Vec::new(),
            package: finding.package,
            ecosystem: finding.ecosystem,
            version: finding.installed,
            purl: finding.purl.unwrap_or_default(),
            source_packages: BTreeSet::new(),
            severity: String::new(),
            fixes: BTreeSet::new(),
            cpe_match: false,
        });
        row.fixes
            .extend(fixes(std::iter::once(finding.fixed.as_str())));
        if row.severity.is_empty()
            || severity_rank(&finding.severity) > severity_rank(&row.severity)
        {
            row.severity = finding.severity;
        }
        row.aliases.extend(finding.aliases);
        row.aliases.push(advisory);
    }
    // OSV-Scanner can emit a GHSA and a language-database record for the same advisory.
    let mut rows: Vec<_> = packages
        .into_values()
        .map(|mut row| {
            row.aliases.sort_unstable();
            row.aliases.dedup();
            if row.aliases.contains(&row.id) {
                row.advisory.clone_from(&row.id);
            } else if let Some(ghsa) = row.aliases.iter().find(|id| id.starts_with("GHSA-")) {
                row.advisory.clone_from(ghsa);
            }
            row.aliases
                .retain(|id| id != &row.advisory && id != &row.id);
            row
        })
        .collect();
    rows.sort_unstable();
    Ok(rows)
}

fn candidate_keys<'a>(
    row: &'a Observation,
    identity: &'a str,
) -> impl Iterator<Item = (&'a str, &'a str, &'a str, &'a str)> {
    let advisory = row.advisory.as_str();
    let package = row.package.as_str();
    std::iter::once(identity)
        .chain((advisory != identity).then_some(advisory))
        .chain(
            row.aliases
                .iter()
                .map(String::as_str)
                .filter(move |&alias| alias != identity && alias != advisory),
        )
        .flat_map(move |id| {
            std::iter::once(package)
                .chain(
                    row.source_packages
                        .iter()
                        .map(String::as_str)
                        .filter(move |&source| source != package),
                )
                .map(move |name| (id, row.ecosystem.as_str(), row.version.as_str(), name))
        })
}

fn reconcile(rows: [Vec<Observation>; 3], engines: &[usize], target: &'static str) -> Explanation {
    let mut observations: Vec<_> = rows
        .into_iter()
        .enumerate()
        .flat_map(|(engine, rows)| rows.into_iter().map(move |row| (engine, Some(row))))
        .collect();
    let mut cve_by_alias = HashMap::<_, BTreeSet<_>>::new();
    for (_, row) in &observations {
        let row = row.as_ref().unwrap();
        if row.id.starts_with("CVE-") {
            for alias in std::iter::once(&row.advisory)
                .chain(&row.aliases)
                .filter(|id| id.starts_with("GHSA-"))
            {
                cve_by_alias.entry(alias).or_default().insert(&row.id);
            }
        }
    }
    let identities: Vec<_> = observations
        .iter()
        .map(|(_, row)| {
            let row = row.as_ref().unwrap();
            cve_by_alias
                .get(&row.id)
                .filter(|ids| ids.len() == 1)
                .and_then(BTreeSet::first)
                .copied()
                .unwrap_or(&row.id)
        })
        .collect();
    let mut index = HashMap::<_, Vec<usize>>::with_capacity(observations.len());
    for (i, (_, row)) in observations.iter().enumerate() {
        let row = row.as_ref().unwrap();
        for key in candidate_keys(row, identities[i]) {
            index.entry(key).or_default().push(i);
        }
    }
    let mut edges = Vec::with_capacity(observations.len());
    for (i, (engine, row)) in observations.iter().enumerate() {
        let row = row.as_ref().unwrap();
        let mut candidates = BTreeSet::new();
        for key in candidate_keys(row, identities[i]) {
            if let Some(matches) = index.get(&key) {
                candidates.extend(matches.iter().copied().filter(|&j| {
                    let (peer, other) = &observations[j];
                    let other = other.as_ref().unwrap();
                    let conflicting_cves = identities[i].starts_with("CVE-")
                        && identities[j].starts_with("CVE-")
                        && identities[i] != identities[j];
                    peer != engine && !conflicting_cves && compatible(row, other)
                }));
            }
        }
        edges.push(candidates);
    }
    drop(index);
    drop(identities);
    drop(cve_by_alias);

    let mut result = Explanation {
        scanners: engines.iter().map(|&engine| SCANNERS[engine]).collect(),
        target,
        agreed: 0,
        auto_resolved: 0,
        needs_review: 0,
        differences: Vec::new(),
    };
    for i in 0..observations.len() {
        if observations[i].1.is_none() {
            continue;
        }
        let group: Vec<_> = std::iter::once(i).chain(edges[i].iter().copied()).collect();
        let scanner_count = group
            .iter()
            .map(|&j| observations[j].0)
            .collect::<BTreeSet<_>>()
            .len();
        // Require unique mutual matches. An alias bridge must not fuse conflicting CVEs or package siblings.
        let ambiguous = scanner_count != group.len()
            || group.iter().any(|&j| {
                edges[j].len() + 1 != group.len()
                    || group.iter().any(|&k| j != k && !edges[j].contains(&k))
            });
        let group = if ambiguous { &group[..1] } else { &group[..] };
        let mut by_engine: Reports<Observation> = [None, None, None];
        for &j in group {
            let (engine, row) = &mut observations[j];
            by_engine[*engine] = row.take();
        }
        add_difference(&mut result, engines, by_engine, ambiguous);
    }
    result
}

fn add_difference(
    result: &mut Explanation,
    engines: &[usize],
    rows: Reports<Observation>,
    ambiguous: bool,
) {
    let present: Vec<_> = rows
        .iter()
        .enumerate()
        .filter_map(|(i, row)| row.as_ref().map(|r| (i, r)))
        .collect();
    let (_, base) = present[0];
    let missing = engines
        .iter()
        .filter(|&&i| rows[i].is_none())
        .map(|&i| LABELS[i])
        .collect::<Vec<_>>();
    let mut review = ambiguous || !missing.is_empty();
    let mut reasons = if present.len() == 1 {
        unpaired(base, &missing.join(" and "), ambiguous)
    } else if !missing.is_empty() {
        vec![format!(
            "{} did not report this advisory for this package.",
            missing.join(" and ")
        )]
    } else {
        Vec::new()
    };

    for (_, other) in present.iter().skip(1) {
        if base.advisory != other.advisory {
            reasons.push(format!(
                "The scanner records link {} and {} as advisory aliases.",
                base.advisory, other.advisory
            ));
        }
        if base.package != other.package {
            reasons.push(format!("Alpine inventory links the binary and source package names {} and {} at version {}.",base.package,other.package,base.version));
        }
    }
    reasons.dedup();
    if present.len() > 1 {
        if result.target == "unverified" {
            review = true;
            reasons.push("The reports do not establish a shared image identity.".into());
        }
        if present.iter().any(|(_, row)| row.severity != base.severity) {
            review = true;
            let values = present
                .iter()
                .map(|(i, row)| format!("{} {}", LABELS[*i], row.severity))
                .collect::<Vec<_>>();
            reasons.push(format!("Severity differs: {}.", values.join(", ")));
        }
        if present.iter().any(|(_, row)| row.fixes != base.fixes) {
            review = true;
            reasons.push("The scanners report different fixed versions.".into());
        }
    }
    let status = if review {
        result.needs_review += 1;
        "needs_review"
    } else if reasons.is_empty() {
        result.agreed += 1;
        return;
    } else {
        result.auto_resolved += 1;
        "auto_resolved"
    };
    let [trivy, grype, osv] = rows;
    result.differences.push(Difference {
        status,
        reasons,
        trivy,
        grype,
        osv,
    });
}

pub fn from_bytes(reports: Reports<&[u8]>, sbom: Option<&[u8]>) -> Result<Vec<u8>> {
    let [trivy, grype, osv] = reports.map(|report| report.map(serde_json::from_slice).transpose());
    let (trivy, grype, osv) = (trivy?, grype?, osv?);
    let sbom = sbom.map(serde_json::from_slice).transpose()?;
    let comparison = compare_reports(
        [trivy.as_ref(), grype.as_ref(), osv.as_ref()],
        sbom.as_ref(),
        true,
    )?;
    let bytes = serde_json::to_vec(&comparison)?;
    ensure!(
        bytes.len() <= MAX_REPORT_BYTES,
        "The discrepancy report exceeds 20 MiB."
    );
    Ok(bytes)
}

const USAGE: &str = "Usage: digestdesk explain [--trivy TRIVY.json] [--grype GRYPE.json] [--osv OSV.json] [--sbom CYCLONEDX.json] [--same-input] [--json]";
fn input(path: &str) -> Result<Value> {
    let mut raw = Vec::new();
    File::open(path)
        .with_context(|| format!("Opening {path}"))?
        .take(MAX_REPORT_BYTES as u64 + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= MAX_REPORT_BYTES,
        "Input exceeds the scan report limit of 20 MiB: {path}"
    );
    serde_json::from_slice(&raw).with_context(|| format!("Reading JSON from {path}"))
}

pub fn cli(args: &[String]) -> Result<()> {
    if args == ["--help"] || args == ["-h"] {
        println!("{USAGE}");
        return Ok(());
    }
    let mut args = args.iter();
    let (mut trivy, mut grype, mut osv, mut sbom) = (None, None, None, None);
    let (mut same, mut json) = (false, false);
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "--trivy" => &mut trivy,
            "--grype" => &mut grype,
            "--osv" => &mut osv,
            "--sbom" => &mut sbom,
            "--json" => {
                json = true;
                continue;
            }
            "--same-input" => {
                same = true;
                continue;
            }
            _ => bail!("{USAGE}"),
        };
        ensure!(slot.is_none(), "{USAGE}");
        *slot = Some(input(args.next().context(USAGE)?)?);
    }
    let report = compare_reports(
        [trivy.as_ref(), grype.as_ref(), osv.as_ref()],
        sbom.as_ref(),
        same,
    )?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "Target: {}. {} agree, {} automatically reconciled, {} need review.",
            report.target, report.agreed, report.auto_resolved, report.needs_review
        );
        for row in &report.differences {
            let f = row
                .trivy
                .as_ref()
                .or(row.grype.as_ref())
                .or(row.osv.as_ref())
                .unwrap();
            println!(
                "[{}] {} {} {}: {}",
                row.status,
                f.advisory,
                f.package,
                f.version,
                row.reasons.join(" ")
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const CVE: &str = "CVE-2024-9143";
    const VERSION: &str = "3.3.2-r0";
    fn pair() -> (Value, Value) {
        let t = json!({"SchemaVersion":2,"ArtifactType":"container_image","Results":[{"Type":"alpine",
            "Packages":[{"Name":"libcrypto3","Version":VERSION,"SrcName":"openssl","SrcVersion":VERSION}],
            "Vulnerabilities":[{"VulnerabilityID":CVE,"PkgName":"libcrypto3","InstalledVersion":VERSION,"Severity":"LOW","FixedVersion":"3.3.2-r1"}]}]});
        let g = json!({"matches":[{"vulnerability":{"id":CVE,"severity":"Low","fix":{"versions":["3.3.2-r1"]}},
            "artifact":{"type":"apk","name":"openssl","version":VERSION}}]});
        (t, g)
    }
    #[test]
    fn reconciles_binary_source_names_and_preserves_versions() -> Result<()> {
        let (t, mut g) = pair();
        let report = compare(&t, &g, None, true)?;
        assert_eq!((report.auto_resolved, report.needs_review), (1, 0));
        assert!(report.differences[0].reasons[0].contains("libcrypto3"));
        assert_eq!(compare(&t, &g, None, false)?.needs_review, 1);
        g["matches"][0]["artifact"]["version"] = json!("3.4-r0");
        assert_eq!(compare(&t, &g, None, true)?.needs_review, 2);
        Ok(())
    }
    #[test]
    fn preserves_disagreements_and_one_sided_cpe_evidence() -> Result<()> {
        let (mut t, mut g) = pair();
        g["matches"][0]["vulnerability"]["severity"] = json!("Critical");
        g["matches"][0]["vulnerability"]["fix"]["versions"] = json!(["3.3.2-r9"]);
        let report = compare(&t, &g, None, true)?;
        assert_eq!((report.auto_resolved, report.needs_review), (0, 1));
        assert!(
            report.differences[0]
                .reasons
                .iter()
                .any(|s| s.contains("Severity differs"))
        );
        assert!(
            report.differences[0]
                .reasons
                .iter()
                .any(|s| s.contains("fixed versions"))
        );
        t["Results"][0]["Vulnerabilities"] = json!([]);
        g["matches"][0]["matchDetails"] = json!([{"type":"cpe-match"}]);
        let report = compare(&t, &g, None, true)?;
        assert_eq!(report.needs_review, 1);
        assert!(
            report.differences[0]
                .reasons
                .iter()
                .any(|s| s.contains("CPE"))
        );
        Ok(())
    }
    #[test]
    fn source_package_cannot_resolve_ambiguous_binary_siblings() -> Result<()> {
        let (mut t, g) = pair();
        let mut second = t["Results"][0]["Vulnerabilities"][0].clone();
        second["PkgName"] = json!("libssl3");
        t["Results"][0]["Vulnerabilities"]
            .as_array_mut()
            .unwrap()
            .push(second);
        t["Results"][0]["Packages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"Name":"libssl3","Version":VERSION,"SrcName":"openssl"}));
        let report = compare(&t, &g, None, true)?;
        assert_eq!((report.auto_resolved, report.needs_review), (0, 3));
        Ok(())
    }
    #[test]
    fn verifies_input_and_cyclonedx_source_evidence() -> Result<()> {
        let (mut t, mut g) = pair();
        t["Results"][0]["Packages"] = json!([]);
        let sbom = json!({"bomFormat":"CycloneDX","components":[{"name":"libcrypto3","version":VERSION,
            "purl":"pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=x86_64&upstream=openssl"}]});
        assert_eq!(compare(&t, &g, Some(&sbom), true)?.auto_resolved, 1);
        t["Metadata"]["ImageID"] = json!(format!("sha256:{}", "a".repeat(64)));
        g["source"]["target"]["imageID"] = json!(format!("sha256:{}", "b".repeat(64)));
        assert!(compare(&t, &g, Some(&sbom), true).is_err());
        Ok(())
    }
    #[test]
    fn compares_all_pairs_and_reports_missing_observations_once() -> Result<()> {
        let cve = "CVE-2099-0002";
        let ghsa = "GHSA-2345-6789-cfgh";
        let trivy = json!({"SchemaVersion":2,"ArtifactType":"container_image","Results":[
            {"Type":"node-pkg","Vulnerabilities":[{"VulnerabilityID":cve,"VendorIDs":[ghsa],"PkgName":"example","InstalledVersion":"1.0.0",
            "Severity":"CRITICAL","FixedVersion":"1.1.0","PkgIdentifier":{"PURL":"pkg:npm/example@1.0.0"}}]}]});
        let grype = json!({"matches":[{"artifact":{"name":"example","version":"1.0.0","type":"npm","purl":"pkg:npm/example@1.0.0"},
            "vulnerability":{"id":cve,"severity":"Critical","fix":{"versions":["1.1.0"]}}}]});
        let osv: Value = serde_json::from_str(
            &include_str!("fixtures/scanners/osv.json").replace("GHSA-fixture", ghsa),
        )?;
        for (reports, names) in [
            ([Some(&trivy), None, Some(&osv)], vec!["trivy", "osv"]),
            ([None, Some(&grype), Some(&osv)], vec!["grype", "osv"]),
            (
                [Some(&trivy), Some(&grype), Some(&osv)],
                vec!["trivy", "grype", "osv"],
            ),
        ] {
            let result = compare_reports(reports, None, true)?;
            assert_eq!(result.scanners, names);
            assert_eq!((result.auto_resolved, result.needs_review), (1, 0));
            assert_eq!(result.differences[0].osv.as_ref().unwrap().advisory, ghsa);
        }
        let mut duplicate = osv.clone();
        let pkg = &mut duplicate["results"][0]["packages"][0];
        let mut ps = pkg["vulnerabilities"][0].clone();
        ps["id"] = json!("PYSEC-2099-8");
        ps["aliases"] = json!([cve, ghsa]);
        ps["affected"][0]["ranges"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"GIT","events":[{"fixed":"abcdef"}]}));
        pkg["vulnerabilities"].as_array_mut().unwrap().push(ps);
        let result = compare_reports([Some(&trivy), Some(&grype), Some(&duplicate)], None, true)?;
        assert_eq!((result.auto_resolved, result.needs_review), (1, 0));
        assert!(
            result.differences[0]
                .osv
                .as_ref()
                .unwrap()
                .aliases
                .contains(&"PYSEC-2099-8".into())
        );
        let empty = json!({"results":[]});
        let result = compare_reports([Some(&trivy), Some(&grype), Some(&empty)], None, true)?;
        assert_eq!(result.needs_review, 1);
        assert_eq!(result.differences.len(), 1);
        assert!(result.differences[0].reasons[0].contains("OSV-Scanner"));
        assert!(result.differences[0].trivy.is_some() && result.differences[0].grype.is_some());
        assert_eq!(
            compare_reports([None, Some(&grype), Some(&osv)], None, false)?.needs_review,
            1
        );
        Ok(())
    }
}
