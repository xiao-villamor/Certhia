use crate::{
    ApiError, ApiResult, App,
    domain::{Package, Report, scanner_names},
    report_branding::{self, Branding},
    report_pdf,
    store::Scan,
};
use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::header,
    response::{IntoResponse, Response},
};
use rust_xlsxwriter::{Format, Workbook};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Write},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

pub async fn download(
    State(app): State<App>,
    Path((id, format)): Path<(String, String)>,
) -> ApiResult<Response> {
    if format == "discrepancies" {
        let scan = app
            .0
            .database
            .replay(&id)
            .await?
            .ok_or_else(|| ApiError::missing("Scan not found."))?;
        if let Some(bytes) = crate::artifacts::discrepancies(&app, &id)
            .await
            .map_err(ApiError::bad)?
        {
            return Ok(attachment(
                &scan_filename(&scan.reference, &scan.platform, &id),
                "application/json",
                "discrepancies.json",
                bytes,
            ));
        }
        return Err(ApiError::bad(
            "A comparison requires completed reports from at least two vulnerability scanners.",
        ));
    }
    let detail = if matches!(
        format.as_str(),
        "sbom" | "cyclonedx" | "spdx" | "raw" | "cbom"
    ) {
        app.0
            .database
            .scan(&id)
            .await?
            .ok_or_else(|| ApiError::missing("Scan not found."))?
    } else {
        crate::read_scan_detail(&app, &id).await?
    };
    let report = detail
        .report
        .ok_or_else(|| ApiError::bad("Wait for the scan to complete."))?;
    let scan = detail.scan;
    let filename = scan_filename(&scan.reference, &scan.platform, &id);
    let raw = match format.as_str() {
        "cbom" => crate::artifacts::cbom(&app, &id)
            .await?
            .into_iter()
            .map(|bytes| ("cbom.cdx.json".to_owned(), bytes))
            .collect(),
        "zip" => {
            let mut files = crate::artifacts::bundle(&app, &id).await?;
            if crate::discrepancies::SCANNERS
                .iter()
                .filter(|engine| {
                    files
                        .iter()
                        .any(|(name, _)| name.strip_suffix(".json") == Some(**engine))
                })
                .count()
                >= 2
                && let Ok(Some(bytes)) = crate::artifacts::discrepancies(&app, &id).await
            {
                files.push(("discrepancies.json".into(), bytes));
            }
            files
        }
        "raw" => crate::artifacts::trivy(&app, &id)
            .await?
            .into_iter()
            .map(|bytes| ("trivy.json".to_owned(), bytes))
            .collect(),
        _ => Vec::new(),
    };
    let reviews = if matches!(format.as_str(), "vex" | "openvex" | "zip") {
        review_notes(&app, &id).await?
    } else {
        BTreeMap::new()
    };
    let branding = if matches!(format.as_str(), "markdown" | "pdf" | "xlsx" | "zip") {
        report_branding::load(&app).await?
    } else {
        Branding::default()
    };
    let scanner = if matches!(format.as_str(), "pdf" | "zip") {
        let (name, version) = sqlx::query_as::<_, (Option<String>, Option<String>)>(
            "SELECT s.scanner, s.scanner_version FROM scan_directory d JOIN scans s USING(id,queued_at) WHERE d.id=$1",
        )
        .bind(crate::key(&id)?)
        .fetch_optional(&app.0.database.primary)
        .await?
        .unwrap_or_default();
        match (name.as_deref(), version) {
            (Some("trivy") | None, Some(version)) => format!("Trivy {version}"),
            (Some("trivy"), None) => "Trivy".into(),
            (Some(_), _) => scanner_names(&report.scanners),
            (None, None) => "Unavailable".into(),
        }
    } else {
        String::new()
    };
    let (mime, extension, body) = tokio::task::spawn_blocking(move || {
        format_report(&scan, &report, &format, raw, &reviews, &branding, &scanner)
    })
    .await
    .map_err(anyhow::Error::from)??;
    Ok(attachment(&filename, mime, extension, body))
}

pub(crate) fn scan_filename(reference: &str, platform: &str, id: &str) -> String {
    let slug = |value: &str| -> String {
        value
            .chars()
            .take(65)
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                    ch
                } else {
                    '-'
                }
            })
            .collect()
    };
    let image = reference.rsplit('/').next().unwrap_or(reference);
    let suffix = id.get(id.len().saturating_sub(8)..).unwrap_or(id);
    format!(
        "certhia-{}-{}-{}",
        slug(image),
        slug(platform),
        slug(suffix)
    )
}

pub(crate) fn attachment(filename: &str, mime: &str, extension: &str, body: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE, mime.to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}.{extension}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        body,
    )
        .into_response()
}

fn format_report(
    scan: &Scan,
    report: &Report,
    format: &str,
    raw: Vec<(String, Vec<u8>)>,
    reviews: &BTreeMap<String, Review>,
    branding: &Branding,
    scanner: &str,
) -> ApiResult<(&'static str, &'static str, Vec<u8>)> {
    Ok(match format {
        "json" => (
            "application/json",
            "json",
            serde_json::to_vec_pretty(&json!({"scan":scan, "report":report}))
                .map_err(anyhow::Error::from)?,
        ),
        "raw" => (
            "application/json",
            "trivy.json",
            raw.into_iter()
                .next()
                .map(|(_, bytes)| bytes)
                .ok_or_else(|| {
                    ApiError::missing("The original scanner output is unavailable for this scan.")
                })?,
        ),
        "cbom" => (
            "application/vnd.cyclonedx+json",
            "cbom.cdx.json",
            raw.into_iter()
                .next()
                .map(|(_, bytes)| bytes)
                .ok_or_else(|| {
                    ApiError::missing(
                        "This scan has no CycloneDX artifact with cryptographic inventory.",
                    )
                })?,
        ),
        "sbom" | "cyclonedx" if report.inventory_available => (
            "application/vnd.cyclonedx+json",
            "cdx.json",
            serde_json::to_vec_pretty(&cyclonedx(scan, report)).map_err(anyhow::Error::from)?,
        ),
        "spdx" if report.inventory_available => (
            "application/spdx+json",
            "spdx.json",
            serde_json::to_vec_pretty(&spdx(scan, report)?).map_err(anyhow::Error::from)?,
        ),
        "sbom" | "cyclonedx" | "spdx" => {
            return Err(ApiError::bad(
                "This scan has no package inventory for an SBOM.",
            ));
        }
        "vex" | "openvex" if !report.findings.is_empty() => (
            "application/ld+json",
            "openvex.json",
            serde_json::to_vec_pretty(&vex(scan, report, reviews)).map_err(anyhow::Error::from)?,
        ),
        "vex" | "openvex" => {
            return Err(ApiError::bad(
                "This scan has no vulnerabilities for a VEX statement.",
            ));
        }
        "markdown" => (
            "text/markdown; charset=utf-8",
            "md",
            rows(scan, report, branding).join("\n").into_bytes(),
        ),
        "pdf" => (
            "application/pdf",
            "pdf",
            report_pdf::build(scan, report, branding, scanner)?,
        ),
        "xlsx" => (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xlsx",
            xlsx(scan, report, branding)?,
        ),
        "zip" => (
            "application/zip",
            "zip",
            archive(scan, report, raw, reviews, branding, scanner)?,
        ),
        _ => return Err(ApiError::missing("Report format not found.")),
    })
}

fn sha256<'a>(reference: &'a str, report: &'a Report) -> Option<&'a str> {
    report
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .or_else(|| reference.rsplit_once("@sha256:").map(|(_, digest)| digest))
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn image_purl(reference: &str, platform: &str, digest: Option<&str>) -> Option<String> {
    let digest = digest?;
    let repository = crate::operations::repository(reference);
    let (_, name) = repository.rsplit_once('/')?;
    let location: String = url::form_urlencoded::byte_serialize(repository.as_bytes()).collect();
    let arch = platform.strip_prefix("linux/")?.replace('/', "");
    Some(format!(
        "pkg:oci/{}@sha256%3A{}?arch={arch}&repository_url={location}",
        name.to_ascii_lowercase(),
        digest.to_ascii_lowercase()
    ))
}

pub const SCHEDULED_SBOM: &str = "scheduled-sbom";

fn inventory_packages(report: &Report) -> impl Iterator<Item = &Package> {
    let mut seen = BTreeSet::new();
    report.packages.iter().filter(move |package| {
        seen.insert((
            &package.ecosystem,
            &package.name,
            &package.version,
            package.purl.as_deref().filter(|purl| !purl.is_empty()),
        ))
    })
}

fn cyclonedx(scan: &Scan, report: &Report) -> Value {
    cyclonedx_inventory(
        &scan.id,
        &scan.reference,
        &scan.platform,
        scan.finished_at.as_deref().unwrap_or(&scan.created_at),
        report,
    )
}

pub fn cyclonedx_inventory(
    id: &str,
    reference: &str,
    platform: &str,
    timestamp: &str,
    report: &Report,
) -> Value {
    let digest = sha256(reference, report);
    let purl = image_purl(reference, platform, digest);
    let mut component = json!({
        "type":"container","name":crate::operations::repository(reference),
        "bom-ref":purl.clone().unwrap_or_else(|| format!("urn:uuid:{id}")),
        "properties":[{"name":"certhia:reference","value":reference},
                      {"name":"certhia:platform","value":platform}]
    });
    if let Some(digest) = digest {
        component["version"] = json!(format!("sha256:{digest}"));
        component["hashes"] = json!([{"alg":"SHA-256","content":digest}]);
    }
    if let Some(purl) = purl {
        component["purl"] = json!(purl);
    }
    json!({
        "$schema":"http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat":"CycloneDX","specVersion":"1.6","version":1,
        "serialNumber":format!("urn:uuid:{id}"),
        "metadata":{"timestamp":timestamp,"component":component,
            "tools":{"components":report.scanners.iter().map(|id| json!({"type":"application","name":scanner_names(std::slice::from_ref(id))})).collect::<Vec<_>>() }},
        "components":inventory_packages(report).map(|p| {
            let mut component = json!({
                "type":"library","name":p.name,"version":p.version,
                "properties":[{"name":"certhia:ecosystem","value":p.ecosystem}]
            });
            if let Some(purl) = p.purl.as_deref().filter(|purl| !purl.is_empty()) {
                component["purl"] = json!(purl);
            }
            component
        }).collect::<Vec<_>>()
    })
}

fn spdx(scan: &Scan, report: &Report) -> Result<Value> {
    let created = chrono::DateTime::parse_from_rfc3339(
        scan.finished_at.as_deref().unwrap_or(&scan.created_at),
    )?
    .with_timezone(&chrono::Utc)
    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let digest = sha256(&scan.reference, report);
    let purl = image_purl(&scan.reference, &scan.platform, digest);
    let version = digest.map(|value| format!("sha256:{value}"));
    let mut container = spdx_package(
        "SPDXRef-Image",
        &scan.reference,
        version.as_deref(),
        purl.as_deref(),
    );
    container["primaryPackagePurpose"] = json!("CONTAINER");

    let mut packages = vec![container];
    let mut relationships = vec![json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": "SPDXRef-Image",
    })];
    for (index, package) in inventory_packages(report).enumerate() {
        let id = format!("SPDXRef-Package-{}", index + 1);
        packages.push(spdx_package(
            &id,
            &package.name,
            Some(&package.version),
            package.purl.as_deref(),
        ));
        relationships.push(json!({
            "spdxElementId": "SPDXRef-Image",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": id,
        }));
    }
    Ok(json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": scan.reference,
        "documentNamespace": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "creationInfo": {
            "created": created,
            "creators": [format!("Tool: {}-{}", crate::PRODUCT_NAME, env!("CARGO_PKG_VERSION"))],
        },
        "packages": packages,
        "relationships": relationships,
    }))
}

fn spdx_package(id: &str, name: &str, version: Option<&str>, purl: Option<&str>) -> Value {
    let mut package = json!({
        "SPDXID": id,
        "name": name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": false,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    });
    if let Some(version) = version.filter(|v| !v.is_empty()) {
        package["versionInfo"] = json!(version);
    }
    if let Some(purl) = purl.filter(|purl| !purl.is_empty()) {
        package["externalRefs"] = json!([{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        }]);
    }
    package
}

struct Review {
    status: String,
    note: String,
    reviewed_at: String,
}

async fn review_notes(app: &App, id: &str) -> Result<BTreeMap<String, Review>> {
    let rows=sqlx::query!("SELECT external_id,status,note,reviewed_at FROM vex_reviews v JOIN advisories a ON a.id=v.advisory_id WHERE scan_id=$1",uuid::Uuid::parse_str(id)?).fetch_all(&app.0.database.primary).await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.external_id,
                Review {
                    status: r.status,
                    note: r.note,
                    reviewed_at: r.reviewed_at.to_rfc3339(),
                },
            )
        })
        .collect())
}

fn vex(scan: &Scan, report: &Report, reviews: &BTreeMap<String, Review>) -> Value {
    let digest = sha256(&scan.reference, report);
    let purl = image_purl(&scan.reference, &scan.platform, digest);
    let mut product = json!({"@id":purl.clone().unwrap_or_else(|| format!("urn:uuid:{}",scan.id))});
    if let Some(purl) = purl {
        product["identifiers"] = json!({"purl":purl});
    }
    if let Some(digest) = digest {
        product["hashes"] = json!({"sha-256":digest});
    }
    let mut advisories = BTreeMap::<&str, BTreeSet<&str>>::new();
    for finding in &report.findings {
        advisories
            .entry(&finding.id)
            .or_default()
            .extend(finding.aliases.iter().map(String::as_str));
    }
    let statements = advisories
        .into_iter()
        .map(|(id, aliases)| {
            let mut statement = json!({
                "vulnerability":{"name":id},"products":[product],"status":"under_investigation",
                "timestamp":scan.finished_at.as_ref().unwrap_or(&scan.created_at)
            });
            if !aliases.is_empty() {
                statement["vulnerability"]["aliases"] = json!(aliases);
            }
            if let Some(review) = reviews.get(id) {
                match review.status.as_str() {
                    "false_positive" if !review.note.trim().is_empty() => {
                        statement["status"] = json!("not_affected");
                        statement["impact_statement"] = json!(review.note.trim());
                        statement["timestamp"] = json!(review.reviewed_at);
                    }
                    "accepted_risk" | "will_not_fix" => {
                        statement["status"] = json!("affected");
                        statement["action_statement"] = json!(
                            "Review the reported finding and apply an available fix or mitigation."
                        );
                        statement["timestamp"] = json!(review.reviewed_at);
                    }
                    _ => {}
                }
            }
            statement
        })
        .collect::<Vec<_>>();
    json!({
        "@context":"https://openvex.dev/ns/v0.2.0","@id":format!("urn:uuid:{}",uuid::Uuid::new_v4()),
        "author":format!("{} workspace", crate::PRODUCT_NAME),"tooling":crate::PRODUCT_NAME,
        "timestamp":crate::store::now(),"version":1,"statements":statements
    })
}

fn escape(text: &str) -> String {
    text.chars()
        .flat_map(|c| match c {
            '\r' | '\n' => vec![' '],
            '<' | '>' | '\\' | '`' | '*' | '_' | '|' | '[' | ']' => vec!['\\', c],
            _ => vec![c],
        })
        .collect()
}

fn rows(scan: &Scan, report: &Report, branding: &Branding) -> Vec<String> {
    let mut lines = vec![
        format!("# {} image report", escape(branding.organization())),
        String::new(),
        format!("- Image: {}", escape(&scan.reference)),
        format!("- Platform: {}", escape(&scan.platform)),
        format!("- Scanners: {}", escape(&scanner_names(&report.scanners))),
        format!("- Created: {}", scan.created_at),
        format!(
            "- Critical: {} | High: {} | Medium: {} | Low: {} | Unknown: {}",
            report.counts.critical,
            report.counts.high,
            report.counts.medium,
            report.counts.low,
            report.counts.unknown
        ),
        String::new(),
        "## Vulnerabilities".into(),
    ];
    for item in &report.findings {
        lines.push(format!(
            "- {} | {} | {} {} | Fix: {} | Detected by: {}{}",
            escape(&item.id),
            escape(&item.severity),
            escape(&item.package),
            escape(&item.installed),
            escape(&item.fixed),
            escape(&scanner_names(&item.detected_by)),
            if item.aliases.is_empty() {
                String::new()
            } else {
                format!(" | Aliases: {}", escape(&item.aliases.join(", ")))
            }
        ));
    }
    lines.push(String::new());
    lines.push("## Configuration, secrets and licenses".into());
    for check in &report.checks {
        lines.push(format!(
            "- {} | {} | {} | {}",
            escape(&check.category),
            escape(&check.severity),
            escape(&check.title),
            escape(&check.target)
        ));
    }
    lines.push(String::new());
    lines.push("## Packages".into());
    for p in &report.packages {
        lines.push(format!(
            "- {} {} ({})",
            escape(&p.name),
            escape(&p.version),
            escape(&p.ecosystem)
        ));
    }
    lines
}

fn xlsx(scan: &Scan, report: &Report, branding: &Branding) -> Result<Vec<u8>> {
    let mut workbook = Workbook::new();
    let strong = Format::new().set_bold().set_background_color(0xE4F4EF);
    let summary = workbook.add_worksheet();
    summary
        .set_name("Summary")?
        .set_column_width(0, 20)?
        .set_column_width(1, 70)?;
    for (index, (name, value)) in [
        ("Organization", branding.organization()),
        ("Image", scan.reference.as_str()),
        ("Platform", scan.platform.as_str()),
        ("Scan date", scan.created_at.as_str()),
        ("Scanners", &scanner_names(&report.scanners)),
    ]
    .into_iter()
    .enumerate()
    {
        summary
            .write_string_with_format(index as u32, 0, name, &strong)?
            .write_string(index as u32, 1, value)?;
    }
    let findings = workbook.add_worksheet();
    findings
        .set_name("Vulnerabilities")?
        .set_freeze_panes(1, 0)?
        .set_column_range_width(0, 8, 25)?;
    findings.write_row_with_format(
        0,
        0,
        [
            "ID",
            "Severity",
            "Ecosystem",
            "Package",
            "Installed",
            "Fixed",
            "Title",
            "Aliases",
            "Detected by",
        ],
        &strong,
    )?;
    for (row, v) in report.findings.iter().enumerate() {
        findings.write_row(
            row as u32 + 1,
            0,
            [
                &v.id,
                &v.severity,
                &v.ecosystem,
                &v.package,
                &v.installed,
                &v.fixed,
                &v.title,
                &v.aliases.join(", "),
                &scanner_names(&v.detected_by),
            ],
        )?;
    }
    let checks = workbook.add_worksheet();
    checks
        .set_name("Checks")?
        .set_freeze_panes(1, 0)?
        .set_column_range_width(0, 5, 26)?;
    checks.write_row_with_format(
        0,
        0,
        ["Type", "ID", "Severity", "Target", "Title", "Detail"],
        &strong,
    )?;
    for (row, v) in report.checks.iter().enumerate() {
        checks.write_row(
            row as u32 + 1,
            0,
            [
                &v.category,
                &v.id,
                &v.severity,
                &v.target,
                &v.title,
                &v.detail,
            ],
        )?;
    }
    let packages = workbook.add_worksheet();
    packages
        .set_name("Packages")?
        .set_freeze_panes(1, 0)?
        .set_column_range_width(0, 2, 26)?;
    packages.write_row_with_format(0, 0, ["Name", "Ecosystem", "Version"], &strong)?;
    for (row, p) in report.packages.iter().enumerate() {
        packages.write_row(row as u32 + 1, 0, [&p.name, &p.ecosystem, &p.version])?;
    }
    Ok(workbook.save_to_buffer()?)
}

fn archive(
    scan: &Scan,
    report: &Report,
    raw: Vec<(String, Vec<u8>)>,
    reviews: &BTreeMap<String, Review>,
    branding: &Branding,
    scanner: &str,
) -> Result<Vec<u8>> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let documents = [
        (
            "report.json",
            serde_json::to_vec_pretty(&json!({"scan":scan, "report":report}))?,
        ),
        (
            "report.md",
            rows(scan, report, branding).join("\n").into_bytes(),
        ),
    ];
    for (name, bytes) in documents {
        zip.start_file(name, options)?;
        zip.write_all(&bytes)?;
    }
    if report.inventory_available {
        zip.start_file("sbom.cdx.json", options)?;
        zip.write_all(&serde_json::to_vec_pretty(&cyclonedx(scan, report))?)?;
        zip.start_file("sbom.spdx.json", options)?;
        zip.write_all(&serde_json::to_vec_pretty(&spdx(scan, report)?)?)?;
    }
    if !report.findings.is_empty() {
        zip.start_file("openvex.json", options)?;
        zip.write_all(&serde_json::to_vec_pretty(&vex(scan, report, reviews))?)?;
    }
    zip.start_file("report.pdf", options)?;
    zip.write_all(&report_pdf::build(scan, report, branding, scanner)?)?;
    zip.start_file("report.xlsx", options)?;
    zip.write_all(&xlsx(scan, report, branding)?)?;
    for (name, bytes) in raw {
        zip.start_file(name, options)?;
        zip.write_all(&bytes)?;
    }
    Ok(zip.finish()?.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> (Scan, Report) {
        let scan = Scan {
            id: "cb9dc8bf-98df-4a65-9945-94db20a0096e".into(),
            reference: "registry.example.test/team/image:latest".into(),
            platform: "linux/amd64".into(),
            status: "completed".into(),
            created_at: "2026-01-01T02:00:00+02:00".into(),
            finished_at: None,
            source: "registry".into(),
            error: None,
            counts: None,
        };
        let report = Report {
            digest: Some(format!("sha256:{}", "a".repeat(64))),
            scanners: vec!["trivy".into()],
            inventory_available: true,
            packages: vec![
                crate::domain::Package {
                    name: "libc".into(),
                    version: "1".into(),
                    ecosystem: "apk".into(),
                    purl: Some("pkg:apk/alpine/libc@1?arch=x86_64".into()),
                    layer_index: None,
                },
                crate::domain::Package {
                    name: "other".into(),
                    version: "2".into(),
                    ecosystem: "apk".into(),
                    purl: None,
                    layer_index: None,
                },
            ],
            ..Report::default()
        };
        (scan, report)
    }

    #[test]
    fn cyclonedx_preserves_component_purls_when_known() {
        let (scan, mut report) = inventory();
        let mut repeated = report.packages[0].clone();
        repeated.layer_index = Some(1);
        report.packages.push(repeated);
        let bom = cyclonedx(&scan, &report);
        assert_eq!(bom["components"].as_array().unwrap().len(), 2);
        assert_eq!(bom["components"][0]["purl"], json!(report.packages[0].purl));
        assert!(bom["components"][1].get("purl").is_none());
        assert_eq!(bom["metadata"]["component"]["type"], "container");
    }

    #[test]
    fn spdx_export_describes_image_and_contains_packages() {
        let (scan, mut report) = inventory();
        let export = |report: &Report| {
            format_report(
                &scan,
                report,
                "spdx",
                vec![],
                &BTreeMap::new(),
                &Branding::default(),
                "",
            )
        };
        let (mime, extension, body) = export(&report).ok().unwrap();
        let doc: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(mime, "application/spdx+json");
        assert_eq!(extension, "spdx.json");
        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        assert_eq!(doc["creationInfo"]["created"], "2026-01-01T00:00:00Z");
        assert_eq!(doc["relationships"][0]["relationshipType"], "DESCRIBES");
        assert_eq!(doc["relationships"][1]["relationshipType"], "CONTAINS");
        assert_eq!(
            doc["relationships"][1]["relatedSpdxElement"],
            doc["packages"][1]["SPDXID"]
        );
        assert_eq!(
            doc["packages"][1]["externalRefs"][0]["referenceLocator"],
            json!(report.packages[0].purl)
        );
        assert!(doc["packages"][2].get("externalRefs").is_none());

        report.inventory_available = false;
        assert!(export(&report).is_err());
    }
}
