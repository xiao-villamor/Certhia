use crate::{
    App,
    artifacts::{Detection, FINDING_SOURCES},
    domain::{Captured, Check, Finding, Package, Report},
    images,
    jobs::Activity,
    scanner::{self, Credentials, Target},
    store::Job,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    path::Path,
};
use tokio::{io::AsyncReadExt, process::Command};

pub async fn scan(
    app: &App,
    job: &Job,
    target: Target<'_>,
    credentials: Option<Credentials>,
    selected: &[String],
    activity: Activity<'_>,
) -> Result<Captured> {
    let data = tokio::fs::canonicalize(&app.0.data).await?;
    let work = tempfile::tempdir_in(data.join("archives"))?;
    let staged = work.path().join("image.tar");
    let mut digest = None;
    let source = match target {
        Target::Remote(reference, insecure) => {
            activity
                .record(
                    "image",
                    "Preparing registry image",
                    "Resolving the platform digest and copying the image for the selected scanners.",
                )
                .await;
            let pinned =
                images::pin(reference, &job.platform, credentials.clone(), insecure).await?;
            digest = pinned.rsplit_once('@').map(|(_, digest)| digest.to_owned());
            Some(images::Source {
                transport: format!("docker://{pinned}"),
                reference: pinned,
                platform: job.platform.clone(),
                auth: credentials,
                host: reference.host.clone(),
                insecure,
            })
        }
        Target::Docker(reference) => {
            crate::discovery::socket().map_err(|error| anyhow::anyhow!(error.1))?;
            activity
                .record(
                    "image",
                    "Preparing Docker image",
                    "Copying the local image for the selected scanners.",
                )
                .await;
            Some(images::Source {
                transport: format!("docker-daemon:{reference}"),
                reference: reference.to_owned(),
                platform: job.platform.clone(),
                auth: None,
                host: String::new(),
                insecure: false,
            })
        }
        Target::Archive(_) => None,
    };
    let archive = if let Target::Archive(path) = target {
        tokio::fs::canonicalize(path).await?
    } else {
        images::copy(
            source.context("Missing image source.")?,
            &format!("docker-archive:{}:certhia:scan", staged.display()),
            "",
            None,
            false,
        )
        .await?;
        staged
    };

    let mut captured = Captured::default();
    let mut succeeded = Vec::new();
    let mut detections = BTreeSet::new();
    let mut failures = Vec::new();
    for &tool in crate::artifacts::TOOLS {
        if !selected.iter().any(|selected| selected == tool) {
            continue;
        }
        let result = if tool == "trivy" {
            scanner::scan(
                Target::Archive(&archive),
                &job.platform,
                None,
                &app.0.cache,
                activity,
            )
            .await
        } else {
            activity
                .record(
                    &format!("{tool}_started"),
                    &format!("Running {tool}"),
                    "Analyzing the image archive.",
                )
                .await;
            run_engine(
                tool,
                &archive,
                &job.platform,
                &data,
                work.path(),
                &job.reference,
            )
            .await
        };
        match result {
            Ok(result) => {
                detections.extend(
                    result
                        .report
                        .findings
                        .iter()
                        .map(|finding| Detection::new(finding, tool)),
                );
                if tool == "trivy" {
                    captured = result;
                    captured
                        .artifacts
                        .retain(|(kind, _)| kind != FINDING_SOURCES);
                } else {
                    merge(&mut captured.report, result.report);
                    captured.artifacts.extend(result.artifacts);
                }
                succeeded.push(tool);
                activity
                    .record(
                        &format!("{tool}_finished"),
                        &format!("{tool} finished"),
                        "Scanner results are ready.",
                    )
                    .await;
            }
            Err(error) => {
                activity
                    .record(
                        &format!("{tool}_failed"),
                        &format!("{tool} failed"),
                        &error.to_string(),
                    )
                    .await;
                failures.push(format!("{tool}: {error}"));
            }
        }
    }
    ensure!(!succeeded.is_empty(), "{}", failures.join("; "));
    captured.report.digest = match digest.or(captured.report.digest.take()) {
        Some(digest) => Some(digest),
        None => Some(archive_identity(&archive).await?),
    };
    captured.report.recount();
    captured.scanner = Some(succeeded.join(", "));
    // A failed engine leaves coverage incomplete, so earlier open findings stay open.
    // When every selected engine succeeds, missing findings resolve as they do for Trivy.
    captured.partial = !failures.is_empty();
    let provenance = serde_json::to_vec(&detections)?;
    ensure!(
        provenance.len() <= scanner::MAX_REPORT_BYTES,
        "Finding evidence exceeds the 20 MB limit."
    );
    captured
        .artifacts
        .push((FINDING_SOURCES.into(), provenance));
    Ok(captured)
}

async fn archive_identity(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut sha = Sha256::new();
    let mut buffer = vec![0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        sha.update(&buffer[..n]);
    }
    let mut identity = String::from("report:");
    for byte in sha.finalize() {
        write!(identity, "{byte:02x}")?;
    }
    Ok(identity)
}

fn merge(report: &mut Report, other: Report) {
    let packages: BTreeMap<_, _> = report
        .packages
        .drain(..)
        .chain(other.packages)
        .map(|package| {
            (
                (
                    package.ecosystem.clone(),
                    package.name.clone(),
                    package.version.clone(),
                    package.purl.clone(),
                ),
                package,
            )
        })
        .collect();
    report.packages = packages.into_values().collect();
    let mut findings: BTreeMap<_, Finding> = BTreeMap::new();
    for finding in report.findings.drain(..).chain(other.findings) {
        let key = (
            finding.id.clone(),
            finding.ecosystem.clone(),
            finding.package.clone(),
            finding.installed.clone(),
            finding.purl.clone(),
        );
        let existing = findings.entry(key).or_insert_with(|| finding.clone());
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
    report.findings = findings.into_values().collect();
    report.checks.extend(other.checks);
    report.inventory_available |= other.inventory_available;
    report.size_bytes = report.size_bytes.or(other.size_bytes);
    if report.os.is_none() {
        report.os = other.os;
    }
}

async fn run_engine(
    tool: &str,
    archive: &Path,
    platform: &str,
    data: &Path,
    work: &Path,
    reference: &str,
) -> Result<Captured> {
    let output = work.join(format!("{tool}.json"));
    let sbom = work.join("sbom.cdx.json");
    let input = format!("docker-archive:{}", archive.display());
    let mut command = Command::new(scanner::binary(tool));
    command.current_dir(work).env("TMPDIR", work);
    match tool {
        "grype" => {
            command
                .env("GRYPE_DB_CACHE_DIR", data.join("grype"))
                .env("GRYPE_CHECK_FOR_APP_UPDATE", "false")
                .args([
                    "--quiet",
                    "--by-cve",
                    "--output",
                    "json",
                    "--platform",
                    platform,
                    "--file",
                ])
                .arg(&output)
                .arg("--")
                .arg(input);
        }
        "syft" => {
            command
                .env("SYFT_CACHE_DIR", data.join("syft"))
                .env("SYFT_CHECK_FOR_APP_UPDATE", "false")
                .env("SYFT_FILE_METADATA_SELECTION", "none")
                .args([
                    "scan",
                    "--quiet",
                    "--platform",
                    platform,
                    "--source-name",
                    reference,
                ])
                .arg("--output")
                .arg(format!("syft-json={}", output.display()))
                .arg("--output")
                .arg(format!("cyclonedx-json={}", sbom.display()))
                .arg("--")
                .arg(input);
        }
        "dockle" => {
            let cache = work.join("dockle-cache");
            tokio::fs::create_dir(&cache).await?;
            command
                .args([
                    "--quiet",
                    "--format",
                    "json",
                    "--exit-code",
                    "0",
                    "--cache-dir",
                ])
                .arg(cache)
                .arg("--input")
                .arg(archive)
                .arg("--output")
                .arg(&output);
        }
        "osv" => {
            command
                .env("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", data.join("osv"))
                .args([
                    "scan",
                    "image",
                    "--archive",
                    "--no-resolve",
                    "--allow-no-lockfiles",
                    "--format",
                    "json",
                    "--output-file",
                ])
                .arg(&output)
                .arg("--")
                .arg(archive);
        }
        "dive" => {
            command
                .env_remove("CI")
                .args(["--source", "docker-archive", "--json"])
                .arg(&output)
                .arg("--")
                .arg(archive);
        }
        _ => bail!("Unknown scanner."),
    }

    let (status, _) = scanner::observe(command, tool, |_| async {}).await?;
    // OSV-Scanner exits 1 when vulnerabilities are found, with a valid report.
    ensure!(
        status.success() || (tool == "osv" && status.code() == Some(1)),
        "{tool} exited with {status}."
    );
    let bytes = read_report(&output).await?;
    let reference = reference.to_owned();
    let syft = tool == "syft";
    let tool = tool.to_owned();
    let mut captured = tokio::task::spawn_blocking(move || {
        let mut json: Value = serde_json::from_slice(&bytes).context("Invalid scanner JSON.")?;
        let report = parse(&tool, &mut json, &reference)?;
        let bytes = if tool == "dockle" {
            serde_json::to_vec(&json)?
        } else {
            bytes
        };
        Ok::<_, anyhow::Error>(Captured {
            report,
            artifacts: vec![(tool, bytes)],
            ..Captured::default()
        })
    })
    .await??;
    if syft {
        captured
            .artifacts
            .push(("sbom".into(), read_report(&sbom).await?));
    }
    Ok(captured)
}

async fn read_report(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    tokio::fs::File::open(path)
        .await?
        .take(scanner::MAX_REPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() <= scanner::MAX_REPORT_BYTES,
        "The scanner report exceeds the 20 MB limit."
    );
    Ok(bytes)
}

fn parse(tool: &str, json: &mut Value, reference: &str) -> Result<Report> {
    let mut report = Report::default();
    match tool {
        "grype" => parse_grype(json, &mut report)?,
        "syft" => parse_syft(json, &mut report)?,
        "dockle" => parse_dockle(json, reference, &mut report)?,
        "osv" => parse_osv(json, &mut report)?,
        "dive" => parse_dive(json, reference, &mut report)?,
        _ => bail!("Unknown scanner."),
    }
    Ok(report)
}

fn rows(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten()
}

fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name].as_str().unwrap_or_default()
}

fn package(value: &Value, kind: &str, distro: &str) -> Result<Package> {
    let name = field(value, "name");
    ensure!(!name.is_empty(), "A scanner package is missing its name.");
    let ecosystem = match kind
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "apk" | "alpine" => "alpine".into(),
        "deb" | "rpm" if !distro.is_empty() => distro.to_ascii_lowercase(),
        "python" | "pypi" => "python-pkg".into(),
        "npm" => "node-pkg".into(),
        "java-archive" | "maven" => "java-archive".into(),
        "go" | "go-module" => "gomod".into(),
        "gem" | "rubygems" => "gemspec".into(),
        "" => "package".into(),
        kind => kind.to_owned(),
    };
    Ok(Package {
        name: name.to_owned(),
        version: field(value, "version").to_owned(),
        ecosystem,
        layer_index: None,
        purl: value["purl"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
    })
}

fn finding(
    package: &Package,
    id: &str,
    title: &str,
    severity: &str,
    fixed: String,
) -> Result<Finding> {
    ensure!(
        !id.is_empty(),
        "A scanner advisory is missing its identifier."
    );
    let upper = severity.to_ascii_uppercase();
    Ok(Finding {
        id: id.to_owned(),
        ecosystem: package.ecosystem.clone(),
        package: package.name.clone(),
        installed: package.version.clone(),
        purl: package.purl.clone(),
        fixed,
        severity: if severity_rank(&upper) == 0 {
            "UNKNOWN".into()
        } else {
            upper
        },
        title: title.to_owned(),
    })
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

fn parse_grype(json: &Value, report: &mut Report) -> Result<()> {
    ensure!(json["matches"].is_array(), "Invalid Grype report.");
    for matched in rows(&json["matches"]) {
        let artifact = &matched["artifact"];
        let package = package(
            artifact,
            field(artifact, "type"),
            field(&json["distro"], "name"),
        )?;
        let vuln = &matched["vulnerability"];
        report.findings.push(finding(
            &package,
            field(vuln, "id"),
            field(vuln, "description"),
            field(vuln, "severity"),
            strings(&vuln["fix"]["versions"])
                .collect::<Vec<_>>()
                .join(", "),
        )?);
    }
    Ok(())
}

fn parse_syft(json: &Value, report: &mut Report) -> Result<()> {
    ensure!(json["artifacts"].is_array(), "Invalid Syft report.");
    let distro = &json["distro"];
    let layers: BTreeMap<_, _> = rows(&json["source"]["metadata"]["layers"])
        .enumerate()
        .filter_map(|(index, layer)| Some((layer["digest"].as_str()?, i32::try_from(index).ok()?)))
        .collect();
    for artifact in rows(&json["artifacts"]) {
        let mut package = package(artifact, field(artifact, "type"), field(distro, "id"))?;
        package.layer_index = rows(&artifact["locations"])
            .filter_map(|location| layers.get(field(location, "layerID")).copied())
            .min();
        report.packages.push(package);
    }
    report.inventory_available = true;
    if let Some(name) = distro["prettyName"]
        .as_str()
        .filter(|name| !name.is_empty())
    {
        report.os = Some(name.to_owned());
    }
    report.size_bytes = json["source"]["metadata"]["imageSize"].as_u64();
    Ok(())
}

fn strings(value: &Value) -> impl Iterator<Item = &str> {
    rows(value).filter_map(Value::as_str)
}

fn parse_dockle(json: &mut Value, reference: &str, report: &mut Report) -> Result<()> {
    let details = json["details"]
        .as_array_mut()
        .context("Invalid Dockle report.")?;
    for detail in details {
        let code = field(detail, "code").to_owned();
        let level = field(detail, "level");
        let severity = match level {
            "FATAL" => "HIGH",
            "WARN" => "MEDIUM",
            "INFO" => "LOW",
            _ => continue,
        };
        if code == "CIS-DI-0010" {
            // That rule can return matched credential values.
            detail["alerts"] = serde_json::json!(["Potential credentials detected in the image."]);
        }
        report.checks.push(Check {
            category: "compliance".into(),
            id: code,
            target: reference.to_owned(),
            severity: severity.into(),
            title: field(detail, "title").to_owned(),
            detail: strings(&detail["alerts"]).collect::<Vec<_>>().join("\n"),
        });
    }
    Ok(())
}

fn parse_osv(json: &Value, report: &mut Report) -> Result<()> {
    ensure!(json["results"].is_array(), "Invalid OSV-Scanner report.");
    for result in rows(&json["results"]) {
        for entry in rows(&result["packages"]) {
            let info = &entry["package"];
            let package = package(info, field(info, "ecosystem"), "")?;
            for vuln in rows(&entry["vulnerabilities"]) {
                let id = field(vuln, "id");
                let group = rows(&entry["groups"])
                    .find(|group| strings(&group["ids"]).any(|candidate| candidate == id));
                let cve = group
                    .into_iter()
                    .flat_map(|group| strings(&group["aliases"]))
                    .chain(strings(&vuln["aliases"]))
                    .find(|alias| alias.starts_with("CVE-"));
                let score = group.and_then(|g| field(g, "max_severity").parse::<f64>().ok());
                let detail = field(&vuln["databaseSpecific"], "severity");
                let severity = match score {
                    Some(score) if score >= 9.0 => "CRITICAL",
                    Some(score) if score >= 7.0 => "HIGH",
                    Some(score) if score >= 4.0 => "MEDIUM",
                    Some(score) if score > 0.0 => "LOW",
                    _ => detail,
                };
                let fixed = rows(&vuln["affected"])
                    .filter(|affected| {
                        let name = field(&affected["package"], "name");
                        name == package.name || info["os_package_name"].as_str() == Some(name)
                    })
                    .flat_map(|affected| rows(&affected["ranges"]))
                    .flat_map(|range| rows(&range["events"]))
                    .filter_map(|event| event["fixed"].as_str())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ");
                report.findings.push(finding(
                    &package,
                    cve.unwrap_or(id),
                    field(vuln, "summary"),
                    severity,
                    fixed,
                )?);
            }
        }
    }
    Ok(())
}

fn parse_dive(json: &Value, reference: &str, report: &mut Report) -> Result<()> {
    let image = &json["image"];
    let score = image["efficiencyScore"]
        .as_f64()
        .context("Missing Dive efficiency score.")?;
    let wasted = image["inefficientBytes"]
        .as_u64()
        .context("Missing Dive inefficient byte count.")?;
    report.checks.push(Check {
        category: "efficiency".into(),
        id: "dive-efficiency".into(),
        target: reference.to_owned(),
        severity: if wasted == 0 {
            "INFO".into()
        } else {
            "LOW".into()
        },
        title: "Image layer efficiency".into(),
        detail: format!("{:.1}% efficient, {wasted} bytes wasted.", score * 100.0),
    });
    report.size_bytes = image["sizeBytes"].as_u64();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE: &str = "registry.example/team/image:latest";

    #[test]
    fn grype_maps_findings_and_fixes() -> Result<()> {
        let mut json = serde_json::from_str(include_str!("fixtures/scanners/grype.json"))?;
        let report = parse("grype", &mut json, IMAGE)?;
        let finding = &report.findings[0];
        assert_eq!(finding.id, "CVE-2099-0001");
        assert_eq!(finding.ecosystem, "alpine");
        assert_eq!(finding.installed, "3.5.0-r0");
        assert_eq!(finding.fixed, "3.5.1-r0");
        assert_eq!(finding.severity, "HIGH");
        let provenance = Detection::new(finding, "grype");
        assert_eq!(provenance.scanner, "grype");
        assert_eq!(
            provenance.purl.as_deref(),
            Some("pkg:apk/alpine/openssl@3.5.0-r0")
        );
        assert!(!report.inventory_available);
        Ok(())
    }

    #[test]
    fn syft_maps_package_inventory_and_layers() -> Result<()> {
        let mut json = serde_json::from_str(include_str!("fixtures/scanners/syft.json"))?;
        let report = parse("syft", &mut json, IMAGE)?;
        assert!(report.inventory_available);
        assert_eq!(report.packages.len(), 1);
        assert_eq!(report.packages[0].name, "openssl");
        assert_eq!(report.packages[0].layer_index, Some(1));
        assert_eq!(report.os.as_deref(), Some("Alpine Linux 3.22"));
        assert_eq!(report.size_bytes, Some(12345));
        Ok(())
    }

    #[test]
    fn dockle_maps_failed_checks_and_redacts_credential_alerts() -> Result<()> {
        let mut json = serde_json::from_str(include_str!("fixtures/scanners/dockle.json"))?;
        let report = parse("dockle", &mut json, IMAGE)?;
        assert_eq!(report.checks.len(), 2);
        assert_eq!(report.checks[0].category, "compliance");
        assert_eq!(report.checks[0].detail, "Last user should not be root");
        assert_eq!(report.checks[0].target, IMAGE);
        assert!(!report.checks[1].detail.contains("fixture-secret"));
        assert!(!json.to_string().contains("fixture-secret"));
        Ok(())
    }

    #[test]
    fn osv_maps_cve_aliases_severity_and_package_fixes() -> Result<()> {
        let mut json = serde_json::from_str(include_str!("fixtures/scanners/osv.json"))?;
        let report = parse("osv", &mut json, IMAGE)?;
        let finding = &report.findings[0];
        assert_eq!(finding.id, "CVE-2099-0002");
        assert_eq!(finding.ecosystem, "node-pkg");
        assert_eq!(finding.severity, "CRITICAL");
        assert_eq!(finding.fixed, "1.1.0");
        assert!(
            parse("osv", &mut serde_json::json!({"results": []}), IMAGE)?
                .findings
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn dive_maps_layer_efficiency() -> Result<()> {
        let mut json = serde_json::from_str(include_str!("fixtures/scanners/dive.json"))?;
        let report = parse("dive", &mut json, IMAGE)?;
        assert_eq!(report.size_bytes, Some(2000));
        assert_eq!(report.checks[0].category, "efficiency");
        assert_eq!(
            report.checks[0].detail,
            "93.1% efficient, 138 bytes wasted."
        );
        Ok(())
    }
}
