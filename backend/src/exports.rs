use crate::{
    ApiError, ApiResult, App,
    domain::Report,
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
    let detail = app
        .0
        .database
        .scan(&id)
        .await?
        .ok_or_else(|| ApiError::missing("Scan not found."))?;
    let report = detail
        .report
        .ok_or_else(|| ApiError::bad("Wait for the scan to complete."))?;
    let scan = detail.scan;
    let raw = match format.as_str() {
        "cbom" => crate::artifacts::cbom(&app, &id)
            .await?
            .into_iter()
            .map(|bytes| ("cbom.cdx.json".to_owned(), bytes))
            .collect(),
        "zip" => crate::artifacts::bundle(&app, &id).await?,
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
            (Some(name), Some(version)) => format!("{name} {version}"),
            (Some(name), None) => name.to_owned(),
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
    Ok((
        [
            (header::CONTENT_TYPE, mime.to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"digestdesk-{id}.{extension}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
        ],
        body,
    )
        .into_response())
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
            serde_json::to_vec_pretty(&sbom(scan, report)).map_err(anyhow::Error::from)?,
        ),
        "sbom" | "cyclonedx" => {
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

fn sha256<'a>(scan: &'a Scan, report: &'a Report) -> Option<&'a str> {
    report
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .or_else(|| {
            scan.reference
                .rsplit_once("@sha256:")
                .map(|(_, digest)| digest)
        })
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn image_purl(scan: &Scan, digest: Option<&str>) -> Option<String> {
    let digest = digest?;
    let repository = crate::operations::repository(&scan.reference);
    let (_, name) = repository.rsplit_once('/')?;
    let location: String = url::form_urlencoded::byte_serialize(repository.as_bytes()).collect();
    let arch = scan.platform.strip_prefix("linux/")?.replace('/', "");
    Some(format!(
        "pkg:oci/{}@sha256%3A{}?arch={arch}&repository_url={location}",
        name.to_ascii_lowercase(),
        digest.to_ascii_lowercase()
    ))
}

fn sbom(scan: &Scan, report: &Report) -> Value {
    let digest = sha256(scan, report);
    let purl = image_purl(scan, digest);
    let mut component = json!({
        "type":"container","name":crate::operations::repository(&scan.reference),
        "bom-ref":purl.clone().unwrap_or_else(|| format!("urn:uuid:{}", scan.id)),
        "properties":[{"name":"certhia:reference","value":scan.reference},
                      {"name":"certhia:platform","value":scan.platform}]
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
        "serialNumber":format!("urn:uuid:{}",scan.id),
        "metadata":{"timestamp":scan.finished_at.as_ref().unwrap_or(&scan.created_at),"component":component},
        "components":report.packages.iter().map(|p| json!({
            "type":"library","name":p.name,"version":p.version,
            "properties":[{"name":"certhia:ecosystem","value":p.ecosystem}]
        })).collect::<Vec<_>>()
    })
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
    let digest = sha256(scan, report);
    let purl = image_purl(scan, digest);
    let mut product = json!({"@id":purl.clone().unwrap_or_else(|| format!("urn:uuid:{}",scan.id))});
    if let Some(purl) = purl {
        product["identifiers"] = json!({"purl":purl});
    }
    if let Some(digest) = digest {
        product["hashes"] = json!({"sha-256":digest});
    }
    let advisories: BTreeSet<_> = report
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect();
    let statements = advisories
        .into_iter()
        .map(|id| {
            let mut statement = json!({
                "vulnerability":{"name":id},"products":[product],"status":"under_investigation",
                "timestamp":scan.finished_at.as_ref().unwrap_or(&scan.created_at)
            });
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
            "- {} | {} | {} {} | Fix: {}",
            escape(&item.id),
            escape(&item.severity),
            escape(&item.package),
            escape(&item.installed),
            escape(&item.fixed)
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
        .set_column_range_width(0, 6, 25)?;
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
        zip.write_all(&serde_json::to_vec_pretty(&sbom(scan, report))?)?;
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
