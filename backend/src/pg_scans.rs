use crate::{
    domain::{Check, Counts, Finding, Package, Report},
    postgres::Database,
    store::{Job, Scan, ScanDetail},
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
struct StoredScan {
    id: Uuid,
    reference: String,
    platform: String,
    status: String,
    queued_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    source: String,
    error: Option<String>,
    counts: Option<sqlx::types::Json<Counts>>,
}
impl From<StoredScan> for Scan {
    fn from(row: StoredScan) -> Self {
        Self {
            id: row.id.to_string(),
            reference: row.reference,
            platform: row.platform,
            status: row.status,
            created_at: row.queued_at.to_rfc3339(),
            finished_at: row.finished_at.map(|v| v.to_rfc3339()),
            source: row.source,
            error: row.error,
            counts: row.counts.map(|v| v.0),
        }
    }
}

impl Database {
    pub async fn scan_page(
        &self,
        before: Option<Uuid>,
        limit: i64,
        q: Option<&str>,
        status: Option<&str>,
        repository: Option<&str>,
        platform: Option<&str>,
    ) -> Result<Vec<Scan>> {
        let rows = sqlx::query_as::<_, StoredScan>(
            "SELECT id,reference,platform,status,queued_at,finished_at,source,error,counts
            FROM scans WHERE ($1::uuid IS NULL OR id<$1)
            AND ($3::text IS NULL OR reference ILIKE '%'||$3||'%')
            AND ($4::text IS NULL OR status=$4 OR ($4='active' AND status IN ('queued','running')))
            AND ($5::text IS NULL OR reference=$5 OR left(reference,length($5)+1) IN ($5||':',$5||'@'))
            AND ($6::text IS NULL OR platform=$6)
            ORDER BY id DESC LIMIT $2",
        )
        .bind(before)
        .bind(limit)
        .bind(q)
        .bind(status)
        .bind(repository)
        .bind(platform)
        .fetch_all(&self.primary)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
    pub async fn replay(&self, id: &str) -> Result<Option<Job>> {
        let Ok(id) = Uuid::parse_str(id) else {
            return Ok(None);
        };
        let row = sqlx::query!(
            "SELECT s.reference,s.platform,s.registry_profile_id,s.source FROM scan_directory d
            JOIN scans s USING(id,queued_at) WHERE d.id=$1",
            id
        )
        .fetch_optional(&self.primary)
        .await?;
        Ok(row.map(|r| Job {
            id: id.to_string(),
            reference: r.reference,
            platform: r.platform,
            registry_id: r.registry_profile_id.map(|v| v.to_string()),
            source: r.source,
        }))
    }
    pub async fn scan(&self, id: &str) -> Result<Option<ScanDetail>> {
        let Ok(id) = Uuid::parse_str(id) else {
            return Ok(None);
        };
        let mut tx = self.primary.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await?;
        let Some(row) = sqlx::query_as::<_, StoredScan>(
            "SELECT s.id,reference,platform,status,s.queued_at,finished_at,source,error,counts
            FROM scan_directory sd JOIN scans s USING(id,queued_at) WHERE sd.id=$1",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(None);
        };
        let scan: Scan = row.into();
        if scan.status != "completed" {
            return Ok(Some(ScanDetail { scan, report: None }));
        }
        let manifest=sqlx::query!("SELECT d.id,d.digest,d.os,d.size,s.inventory_available,sd.observed_order
            FROM scan_directory sd JOIN scans s USING(id,queued_at) JOIN digests d ON d.id=s.digest_id WHERE sd.id=$1",id)
            .fetch_one(&mut *tx).await?;
        let packages=sqlx::query_as!(Package,"SELECT DISTINCT e.name AS ecosystem,p.name,p.version,p.purl,nullif(dp.layer_index,-1) AS layer_index FROM digest_packages dp
            JOIN packages p ON p.id=dp.package_id JOIN ecosystems e ON e.id=p.ecosystem_id WHERE dp.digest_id=$1
            ORDER BY ecosystem,p.name,p.version",manifest.id).fetch_all(&mut *tx).await?;
        let findings=sqlx::query_as!(Finding,r#"SELECT a.external_id AS id,e.name AS ecosystem,p.name AS package,p.version AS installed,p.purl,
            coalesce(v.version,'') AS "fixed!",upper(s.name) AS "severity!",coalesce(a.summary,'') AS "title!"
            FROM scan_finding_keys($1,$2) k JOIN packages p ON p.id=k.package_id JOIN ecosystems e ON e.id=p.ecosystem_id
            JOIN advisories a ON a.id=k.advisory_id JOIN severities s ON s.id=a.severity_id
            JOIN findings f ON f.digest_id=$1 AND f.package_id=k.package_id AND f.advisory_id=k.advisory_id
            LEFT JOIN fix_versions v ON v.id=f.fixed_in ORDER BY a.external_id,p.name"#,manifest.id,manifest.observed_order)
            .fetch_all(&mut *tx).await?;
        let checks=sqlx::query_as!(Check,"SELECT category,external_id AS id,target,severity,title,detail FROM scan_checks WHERE scan_id=$1 ORDER BY ordinal",id)
            .fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let report = Report {
            packages,
            findings,
            inventory_available: manifest.inventory_available,
            digest: manifest
                .digest
                .starts_with("sha256:")
                .then_some(manifest.digest),
            counts: scan.counts.clone().unwrap_or_default(),
            checks,
            size_bytes: manifest.size.map(u64::try_from).transpose()?,
            os: manifest.os,
        };
        Ok(Some(ScanDetail {
            scan,
            report: Some(report),
        }))
    }
}
