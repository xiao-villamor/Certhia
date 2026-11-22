use crate::domain::{Counts, Report};
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Registry {
    pub id: String,
    pub name: String,
    pub host: String,
    pub authenticated: bool,
    pub provider: String,
    pub auth_host: Option<String>,
    pub auto_sync: bool,
    pub protocol: String,
    pub skip_tls: bool,
    pub namespace: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Scan {
    pub id: String,
    pub reference: String,
    pub platform: String,
    pub status: String,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub source: String,
    pub error: Option<String>,
    pub counts: Option<Counts>,
}

#[derive(Serialize)]
pub struct ScanDetail {
    #[serde(flatten)]
    pub scan: Scan,
    pub report: Option<Report>,
}

pub struct Job {
    pub id: String,
    pub reference: String,
    pub platform: String,
    pub registry_id: Option<String>,
    pub source: String,
}

pub fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}
