// Point CERTHIA_BENCH_URL at a disposable running instance with the scale fixture.
use serde_json::{Value, json};
use std::sync::LazyLock;
struct Benchmark {
    rt: tokio::runtime::Runtime,
    http: reqwest::Client,
    base: String,
    report: Vec<u8>,
}
static APP: LazyLock<Benchmark> = LazyLock::new(|| {
    let base = std::env::var("CERTHIA_BENCH_URL")
        .expect("Set CERTHIA_BENCH_URL to the disposable benchmark instance");
    let reports=(0..2000).map(|i|json!({"VulnerabilityID":format!("BENCH-DIVAN-{i}"),"PkgName":format!("pkg-{}",i%400),"InstalledVersion":"1","Severity":"HIGH"})).collect::<Vec<_>>();
    let packages = (0..400)
        .map(|i| json!({"Name":format!("pkg-{i}"),"Version":"1"}))
        .collect::<Vec<_>>();
    let report = json!({"SchemaVersion":2,"ArtifactType":"container_image","Results":[{"Type":"apk","Packages":packages,"Vulnerabilities":reports}]});
    Benchmark {
        rt: tokio::runtime::Runtime::new().unwrap(),
        http: reqwest::Client::new(),
        base,
        report: serde_json::to_vec(&report).unwrap(),
    }
});
fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    divan::main();
}
#[divan::bench]
fn ingest_2000() {
    APP.rt.block_on(async {
        APP.http
            .post(format!(
                "{}/api/scans/import?reference=fixture.test/divan:latest&platform=linux/amd64",
                APP.base
            ))
            .header("content-type", "application/json")
            .body(APP.report.clone())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()
    });
}
#[divan::bench(args=["/dashboard","/library/top-packages","/library/advisories?q=2025-001","/repositories/2500/findings","/library/advisories/88/digests","/digests/123000/compare/123001"])]
fn query(path: &str) {
    APP.rt.block_on(async {
        APP.http
            .get(format!("{}/api{}", APP.base, path))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .bytes()
            .await
            .unwrap()
    });
}
