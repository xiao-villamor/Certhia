//! Repeatable, sequential benchmarks for the comparer and report read endpoints.
use crate::{discrepancies, scanner::MAX_REPORT_BYTES};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    time::{Duration, Instant},
};
use url::Url;

const HELP: &str = "digestdesk bench explain (--synthetic N | [--trivy FILE] [--grype FILE] [--osv FILE] [--sbom FILE]) [--same-input] [--iterations N] [--warmup N]\ndigestdesk bench report --base-url URL --scan-id UUID [--iterations N] [--warmup N] (session cookie in CERTHIA_BENCH_COOKIE)\ndigestdesk bench compare BEFORE.json AFTER.json";
fn file(path: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("Opening {path}"))?
        .take(MAX_REPORT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_REPORT_BYTES, "{path} exceeds 20 MiB");
    Ok(bytes)
}
fn number(s: &str, min: usize, max: usize) -> Result<usize> {
    let n = s.parse::<usize>().context("Expected a whole number")?;
    ensure!(
        (min..=max).contains(&n),
        "Expected a value between {min} and {max}"
    );
    Ok(n)
}
#[derive(Default)]
struct Samples(BTreeMap<String, Vec<f64>>);
impl Samples {
    fn record(&mut self, active: bool, phase: &str, start: Instant) {
        if active {
            self.0
                .entry(phase.into())
                .or_default()
                .push(start.elapsed().as_secs_f64() * 1000.0);
        }
    }
    fn finish(self) -> Value {
        Value::Object(
            self.0
                .into_iter()
                .map(|(name, samples)| {
                    let mut sorted = samples.clone();
                    sorted.sort_by(f64::total_cmp);
                    let n = sorted.len();
                    let median = (sorted[(n - 1) / 2] + sorted[n / 2]) / 2.;
                    let p95 = sorted[(95 * n).div_ceil(100) - 1];
                    (
                        name,
                        json!({"medianMs":median,"p95Ms":p95,"samplesMs":samples}),
                    )
                })
                .collect(),
        )
    }
}
fn generate(n: usize) -> Result<(Vec<u8>, Vec<u8>)> {
    let image = format!("sha256:{}", "a".repeat(64));
    let mut trivy = Vec::new();
    let mut grype = Vec::new();
    for i in 0..n {
        let id = format!("CVE-2099-{:06}", 1000 + i);
        let alphabet = b"23456789cfghjmpq";
        let suffix: String = (0..4)
            .rev()
            .map(|shift| alphabet[(i >> (4 * shift)) & 15] as char)
            .collect();
        let ghsa = format!("GHSA-2345-6789-{suffix}");
        let name = format!("sample-{}", i % 60);
        let purl = format!("pkg:pypi/{name}@1.0");
        if i % 5 != 2 {
            trivy.push(json!({"VulnerabilityID":id,"VendorIDs":[ghsa],"PkgName":name,"InstalledVersion":"1.0","PkgIdentifier":{"PURL":purl},"Severity":"HIGH","FixedVersion":"1.1"}));
        }
        if i % 5 != 3 {
            grype.push(json!({"artifact":{"type":"python","name":name,"version":"1.0","purl":purl},"vulnerability":{"id":if i%5==0 {&id} else {&ghsa},"severity":if i%5==4 {"Medium"} else {"High"},"fix":{"versions":["1.1"]}},"relatedVulnerabilities":[{"id":id}]}));
        }
    }
    let t = json!({"SchemaVersion":2,"ArtifactType":"container_image","Metadata":{"ImageID":image},"Results":[{"Type":"python-pkg","Vulnerabilities":trivy}]});
    let g = json!({"source":{"target":{"imageID":image}},"matches":grype});
    Ok((serde_json::to_vec(&t)?, serde_json::to_vec(&g)?))
}
fn fingerprint(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        write!(&mut hex, "{b:02x}").expect("writing to a String");
    }
    hex
}
fn options<'a>(args: &'a [String], allowed: &[&str]) -> Result<(BTreeMap<&'a str, &'a str>, bool)> {
    let mut params = BTreeMap::new();
    let mut same = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "--same-input" && allowed.contains(&"--same-input") {
            same = true;
            continue;
        }
        ensure!(allowed.contains(&arg.as_str()), "{HELP}");
        let value = it.next().context(HELP)?;
        ensure!(
            params.insert(arg.as_str(), value.as_str()).is_none(),
            "Duplicate option {arg}"
        );
    }
    Ok((params, same))
}
fn runs(params: &BTreeMap<&str, &str>) -> Result<(usize, usize)> {
    Ok((
        number(params.get("--warmup").copied().unwrap_or("3"), 0, 200)?,
        number(params.get("--iterations").copied().unwrap_or("20"), 1, 1000)?,
    ))
}
fn explain(args: &[String]) -> Result<Value> {
    let (opt, same) = options(
        args,
        &[
            "--trivy",
            "--grype",
            "--osv",
            "--sbom",
            "--synthetic",
            "--warmup",
            "--iterations",
            "--same-input",
        ],
    )?;
    let (warmup, iterations) = runs(&opt)?;
    let reports = if let Some(n) = opt.get("--synthetic") {
        ensure!(
            !["--trivy", "--grype", "--osv", "--sbom"]
                .iter()
                .any(|k| opt.contains_key(k)),
            "Choose a synthetic size or report files."
        );
        let (trivy, grype) = generate(number(n, 1, 30000)?)?;
        [Some(trivy), Some(grype), None]
    } else {
        let [trivy, grype, osv] = ["--trivy", "--grype", "--osv"]
            .map(|flag| opt.get(flag).map(|path| file(path)).transpose());
        [trivy?, grype?, osv?]
    };
    let sbom = opt.get("--sbom").map(|s| file(s)).transpose()?;
    let [trivy, grype, osv] = reports.each_ref().map(|r| r.as_deref().map(fingerprint));
    let workload = json!({"trivySha256":trivy,"grypeSha256":grype,"osvSha256":osv,
        "sbomSha256":sbom.as_deref().map(fingerprint),"sameInput":same});
    let mut samples = Samples::default();
    let mut counts = Value::Null;
    for i in 0..(warmup + iterations) {
        let active = i >= warmup;
        let start = Instant::now();
        let phase = start;
        let [trivy, grype, osv] = reports
            .each_ref()
            .map(|r| r.as_deref().map(serde_json::from_slice).transpose());
        let parsed = [trivy?, grype?, osv?];
        let inventory = sbom.as_deref().map(serde_json::from_slice).transpose()?;
        samples.record(active, "parse", phase);
        let phase = Instant::now();
        let result = discrepancies::compare_reports(
            parsed.each_ref().map(Option::as_ref),
            inventory.as_ref(),
            same,
        )?;
        samples.record(active, "reconcile", phase);
        let phase = Instant::now();
        let encoded = serde_json::to_vec(&result)?;
        std::hint::black_box(&encoded);
        samples.record(active, "serialize", phase);
        samples.record(active, "total", start);
        if i == 0 {
            counts = json!({"agreed":result.agreed,"autoResolved":result.auto_resolved,"needsReview":result.needs_review,"outputSha256":fingerprint(&encoded)});
        }
    }
    Ok(
        json!({"suite":"explain","version":1,"release":!cfg!(debug_assertions),"workload":workload,"warmup":warmup,"iterations":iterations,"result":counts,"phases":samples.finish()}),
    )
}
async fn report(args: &[String]) -> Result<Value> {
    let (opt, _) = options(
        args,
        &["--base-url", "--scan-id", "--warmup", "--iterations"],
    )?;
    let (warmup, iterations) = runs(&opt)?;
    let base = Url::parse(opt.get("--base-url").context(HELP)?)?;
    ensure!(
        base.scheme() == "https"
            || base.scheme() == "http"
                && matches!(base.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")),
        "Use HTTPS or local loopback HTTP."
    );
    ensure!(
        base.username().is_empty()
            && base.password().is_none()
            && base.query().is_none()
            && base.fragment().is_none(),
        "Use a base URL without credentials, a query, or a fragment."
    );
    let id = uuid::Uuid::parse_str(opt.get("--scan-id").context(HELP)?)?;
    let cookie = std::env::var("CERTHIA_BENCH_COOKIE")
        .context("Set CERTHIA_BENCH_COOKIE to a session for the test instance")?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(40))
        .build()?;
    let url = base.join(&format!("/api/scans/{id}"))?;
    let detail: Value = client
        .get(url.clone())
        .header("Cookie", &cookie)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(detail["status"] == "completed", "Choose a completed scan");
    let scanners = detail["report"]["scanners"].as_array();
    let mut endpoints = vec![("scan", ""), ("json", "/report/json")];
    if detail["report"]["inventoryAvailable"] == true {
        endpoints.push(("sbom", "/report/sbom"));
    }
    if scanners.is_some_and(|s| {
        discrepancies::SCANNERS
            .iter()
            .filter(|e| s.iter().any(|x| x == **e))
            .count()
            >= 2
    }) {
        endpoints.push(("discrepancies", "/report/discrepancies"));
    }
    let mut samples = Samples::default();
    let mut sizes = BTreeMap::new();
    for i in 0..(warmup + iterations) {
        for (name, path) in &endpoints {
            let start = Instant::now();
            let response = client
                .get(format!("{url}{path}"))
                .header("Cookie", &cookie)
                .send()
                .await?
                .error_for_status()?;
            ensure!(
                response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|s| s.contains("json")),
                "Expected JSON for {name}"
            );
            let bytes = response.bytes().await?;
            samples.record(i >= warmup, name, start);
            sizes.insert(*name, bytes.len());
        }
    }
    Ok(
        json!({"suite":"report","version":1,"release":!cfg!(debug_assertions),"workload":{"scanId":id,"origin":base.origin().ascii_serialization()},"warmup":warmup,"iterations":iterations,"bytes":sizes,"phases":samples.finish()}),
    )
}
fn comparison(args: &[String]) -> Result<Value> {
    let [before, after] = args else {
        bail!("{HELP}")
    };
    let before: Value = serde_json::from_slice(&file(before)?)?;
    let after: Value = serde_json::from_slice(&file(after)?)?;
    for key in ["suite", "version", "release", "workload", "result"] {
        ensure!(
            before[key] == after[key],
            "Incomparable runs: {key} differs."
        );
    }
    let mut phases = BTreeMap::new();
    for (key, values) in before["phases"]
        .as_object()
        .context("Missing benchmark phases")?
    {
        let a = values["medianMs"]
            .as_f64()
            .context("Missing baseline median")?;
        let b = after["phases"][key]["medianMs"]
            .as_f64()
            .context("Missing candidate median")?;
        phases.insert(key,json!({"beforeMedianMs":a,"afterMedianMs":b,"beforeP95Ms":values["p95Ms"],"afterP95Ms":after["phases"][key]["p95Ms"],"medianChangePercent":(a>0.).then(||(b-a)*100./a)}));
    }
    Ok(json!({"suite":before["suite"],"phases":phases}))
}
pub async fn cli(args: &[String]) -> Result<()> {
    if args.is_empty() || args == ["--help"] {
        println!("{HELP}");
        return Ok(());
    }
    let value = match args[0].as_str() {
        "explain" => explain(&args[1..])?,
        "report" => report(&args[1..]).await?,
        "compare" => comparison(&args[1..])?,
        _ => bail!("{HELP}"),
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
