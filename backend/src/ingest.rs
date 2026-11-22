use crate::{
    artifact_blob,
    domain::{Captured, ImageReference},
    operations::repository,
    postgres::Database,
};
use anyhow::{Context, Result, ensure};
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use std::path::Path;
use uuid::Uuid;

fn encode_row(buf: &mut Vec<u8>, fields: [Option<&str>; 8], layer: i32) {
    buf.extend_from_slice(&9i16.to_be_bytes());
    for field in fields {
        match field {
            None => buf.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(s) => {
                buf.extend_from_slice(&(s.len() as i32).to_be_bytes());
                buf.extend_from_slice(s.as_bytes());
            }
        }
    }
    buf.extend_from_slice(&4i32.to_be_bytes());
    buf.extend_from_slice(&layer.to_be_bytes());
}

async fn stage(tx: &mut Transaction<'_, Postgres>, captured: &Captured) -> Result<()> {
    sqlx::query("CREATE TEMP TABLE observations(ecosystem text,name text,version text,external_id text,severity text,fixed text,title text,purl text,layer_index integer) ON COMMIT DROP").execute(&mut **tx).await?;
    let mut copy = tx
        .copy_in_raw("COPY observations FROM STDIN (FORMAT binary)")
        .await?;
    let mut buf = b"PGCOPY\n\xff\r\n\0\0\0\0\0\0\0\0\0".to_vec();
    let packages = captured.report.packages.iter().map(|p| {
        (
            [
                Some(p.ecosystem.as_str()),
                Some(p.name.as_str()),
                Some(p.version.as_str()),
                None,
                None,
                None,
                None,
                p.purl.as_deref(),
            ],
            p.layer_index.unwrap_or(-1),
        )
    });
    let findings = captured.report.findings.iter().map(|f| {
        (
            [
                Some(f.ecosystem.as_str()),
                Some(f.package.as_str()),
                Some(f.installed.as_str()),
                Some(f.id.as_str()),
                Some(f.severity.as_str()),
                Some(f.fixed.as_str()),
                Some(f.title.as_str()),
                f.purl.as_deref(),
            ],
            -1,
        )
    });
    for (row, layer) in packages.chain(findings) {
        encode_row(&mut buf, row, layer);
        if buf.len() >= 64 * 1024 {
            copy.send(buf.as_slice()).await?;
            buf.clear();
        }
    }
    buf.extend_from_slice(&(-1i16).to_be_bytes());
    copy.send(buf.as_slice()).await?;
    copy.finish().await?;
    Ok(())
}

pub async fn import(
    db: &Database,
    data: &Path,
    reference: &ImageReference,
    platform: &str,
    captured: Captured,
) -> Result<Uuid> {
    write(db, data, reference, platform, captured, None).await
}

#[derive(Clone, Copy)]
pub struct Lease {
    pub scan: Uuid,
    pub token: Uuid,
    pub owner: Uuid,
}

pub async fn write(
    db: &Database,
    data: &Path,
    reference: &ImageReference,
    platform: &str,
    captured: Captured,
    lease: Option<Lease>,
) -> Result<Uuid> {
    use std::fmt::Write;
    let (raw_ref, digest) = if let Some(raw) = &captured.raw {
        let mut hash = String::with_capacity(64);
        for byte in Sha256::digest(raw) {
            write!(hash, "{byte:02x}")?;
        }
        let raw_ref = artifact_blob::persist(db, data, &hash, raw).await?;
        (
            Some(raw_ref),
            captured
                .report
                .digest
                .clone()
                .unwrap_or_else(|| format!("report:{hash}")),
        )
    } else {
        (
            None,
            captured
                .report
                .digest
                .clone()
                .context("Scan has no image identity.")?,
        )
    };
    let id = lease.map_or_else(Uuid::now_v7, |lease| lease.scan);
    let queued = Utc::now();
    let mut artifacts = Vec::with_capacity(captured.artifacts.len());
    for (kind, bytes) in &captured.artifacts {
        let mut hash = String::with_capacity(64);
        for byte in Sha256::digest(bytes) {
            write!(hash, "{byte:02x}")?;
        }
        artifacts.push((
            kind.clone(),
            artifact_blob::persist(db, data, &hash, bytes).await?,
        ));
    }
    sqlx::query("SELECT prepare_storage_months($1)")
        .bind(queued)
        .execute(&db.primary)
        .await?;
    for attempt in 0..5 {
        let mut tx = db.primary.begin().await?;
        let result: Result<()> = async {
            sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE").execute(&mut *tx).await?;
            let registry = sqlx::query_scalar!(
                r#"WITH new_registry AS (
                    INSERT INTO registries(id,host,name) VALUES($1,$2,$2)
                    ON CONFLICT(host) DO NOTHING RETURNING id
                ) SELECT id AS "id!" FROM new_registry UNION ALL SELECT id FROM registries WHERE host=$2"#,
                Uuid::now_v7(), reference.host
            ).fetch_one(&mut *tx).await?;
            let repo_name = if reference.host=="local" && reference.value.starts_with("sha256:"){reference.value.as_str()}else{repository(&reference.value)};
            let name = repo_name.split_once('/').map_or(repo_name,|(_,name)|name);
            let repo_id = sqlx::query_scalar!(
                r#"WITH new_repo AS (
                    INSERT INTO repositories(registry_id,name) VALUES($1,$2)
                    ON CONFLICT(registry_id,name) DO NOTHING RETURNING id
                ) SELECT id AS "id!" FROM new_repo UNION ALL
                    SELECT id FROM repositories WHERE registry_id=$1 AND name=$2"#,
                registry, name
            ).fetch_one(&mut *tx).await?;
            let size = captured.report.size_bytes.map(i64::try_from).transpose()?;
            let digest_id = sqlx::query_scalar!(
                "INSERT INTO digests(digest,os,arch,size) VALUES($1,$2,$3,$4)
                 ON CONFLICT(digest) DO UPDATE SET
                    os=coalesce(digests.os,excluded.os), size=coalesce(digests.size,excluded.size)
                 RETURNING id",
                digest, captured.report.os, platform.split_once('/').map(|(_,arch)| arch), size
            ).fetch_one(&mut *tx).await?;
            let scan=if let Some(lease)=lease {
                sqlx::query!("SELECT finish_scan($1,$2,$3,NULL)",id,lease.token,lease.owner).execute(&mut *tx).await?;
                sqlx::query_scalar!("UPDATE scan_directory SET observed_order=nextval('observation_order') WHERE id=$1 RETURNING scan_no",id)
                    .fetch_one(&mut *tx).await?
            } else {
                let scan=sqlx::query_scalar!(
                    "INSERT INTO scan_directory(id,queued_at,observed_order) VALUES($1,$2,nextval('observation_order')) RETURNING scan_no",id,queued
                ).fetch_one(&mut *tx).await?;
                sqlx::query!("INSERT INTO scans(id,queued_at,reference,platform,status,finished_at)
                    VALUES($1,$2,$3,$4,'completed',now())",id,queued,reference.value,platform).execute(&mut *tx).await?;
                scan
            };
            sqlx::query("UPDATE scans s SET digest_id=$2,repository_id=$3,scanner=$4,raw_report_ref=$5,counts=$6,
                          inventory_available=$7,scanner_version=$8,scanner_db_version=$9 FROM scan_directory sd WHERE sd.id=$1 AND s.id=sd.id AND s.queued_at=sd.queued_at")
                .bind(id).bind(digest_id).bind(repo_id).bind(&captured.scanner).bind(&raw_ref)
                .bind(serde_json::to_value(&captured.report.counts)?).bind(captured.report.inventory_available)
                .bind(&captured.scanner_version).bind(&captured.scanner_db_version)
                .execute(&mut *tx).await?;
            sqlx::query!("INSERT INTO scan_checks(scan_id,ordinal,category,external_id,target,severity,title,detail)
                SELECT $1,(n-1)::integer,j->>'category',j->>'id',j->>'target',j->>'severity',j->>'title',j->>'detail'
                FROM jsonb_array_elements($2) WITH ORDINALITY AS checks(j,n)",id,serde_json::to_value(&captured.report.checks)?)
                .execute(&mut *tx).await?;
            let (kinds,refs):(Vec<_>,Vec<_>)=artifacts.iter().cloned().unzip();
            sqlx::query!("INSERT INTO artifact_refs(scan_id,kind,object_key,owned) SELECT $1,kind,ref,true
                FROM unnest($2::text[],$3::text[]) AS refs(kind,ref)",id,&kinds,&refs).execute(&mut *tx).await?;
            stage(&mut tx,&captured).await?;
            if captured.partial{
                sqlx::query("SET LOCAL certhia.partial = 'on'").execute(&mut *tx).await?;
            }
            sqlx::query!(
                "SELECT merge_observations($1,$2,$3,$4)", digest_id, repo_id, scan, captured.report.inventory_available
            ).execute(&mut *tx).await?;
            if captured.advisory_metadata.as_array().is_some_and(|rows|!rows.is_empty()){
                sqlx::query!("UPDATE advisories a SET description=coalesce(m.description,a.description),refs=coalesce(m.refs,a.refs),
                    published_at=coalesce(m.published_at,a.published_at),modified_at=coalesce(m.modified_at,a.modified_at),
                    cvss_score=coalesce(m.cvss_score,a.cvss_score),cvss_vector=coalesce(m.cvss_vector,a.cvss_vector),
                    epss=coalesce(m.epss,a.epss),kev=coalesce(m.kev,a.kev)
                    FROM jsonb_to_recordset($1) m(id text,description text,refs jsonb,published_at timestamptz,modified_at timestamptz,
                    cvss_score real,cvss_vector text,epss real,kev boolean) WHERE a.external_id=m.id AND a.source='trivy'
                    AND (a.modified_at IS NULL OR m.modified_at>=a.modified_at) AND
                    (a.description,a.refs,a.published_at,a.modified_at,a.cvss_score,a.cvss_vector,a.epss,a.kev) IS DISTINCT FROM
                    (coalesce(m.description,a.description),coalesce(m.refs,a.refs),coalesce(m.published_at,a.published_at),coalesce(m.modified_at,a.modified_at),
                    coalesce(m.cvss_score,a.cvss_score),coalesce(m.cvss_vector,a.cvss_vector),coalesce(m.epss,a.epss),coalesce(m.kev,a.kev))",
                    captured.advisory_metadata).execute(&mut *tx).await?;
            }
            crate::watches::record(&mut tx,id,digest_id,&reference.value,platform).await?;
            if let Some(tag) = reference.value.strip_prefix(repo_name).and_then(|suffix| suffix.strip_prefix(':')) {
                sqlx::query!(
                    "INSERT INTO image_tags(repository_id,tag,platform,digest_id,updated_at) VALUES($1,$2,$3,$4,$5)
                     ON CONFLICT(repository_id,tag,platform) DO UPDATE SET digest_id=excluded.digest_id,updated_at=excluded.updated_at
                     WHERE image_tags.updated_at<=excluded.updated_at",
                    repo_id,tag,platform,digest_id,queued
                ).execute(&mut *tx).await?;
            }
            tx.commit().await?;
            Ok(())
        }.await;
        if let Err(err) = result {
            let transient = err
                .downcast_ref::<sqlx::Error>()
                .and_then(|e| e.as_database_error())
                .and_then(|e| e.code())
                .is_some_and(|code| matches!(code.as_ref(), "40001" | "40P01"));
            if !transient || attempt == 4 {
                return Err(err);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10 << attempt)).await;
        } else {
            return Ok(id);
        }
    }
    unreachable!()
}

pub async fn reimport(data: &Path, args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 3,
        "usage: digestdesk reimport REFERENCE PLATFORM TRIVY_JSON"
    );
    let reference = ImageReference::parse(&args[0], None)?;
    ensure!(
        crate::domain::PLATFORMS.contains(&args[1].as_str()),
        "unsupported platform"
    );
    let path = args[2].clone();
    let captured = tokio::task::spawn_blocking(move || -> Result<_> {
        use std::io::{BufRead, BufReader, Read};
        let mut file = BufReader::new(std::fs::File::open(path)?);
        let reader: Box<dyn Read> = if file.fill_buf()?.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            Box::new(zstd::Decoder::with_buffer(file)?)
        } else {
            Box::new(file)
        };
        let mut bytes = Vec::new();
        reader
            .take(crate::scanner::MAX_REPORT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= crate::scanner::MAX_REPORT_BYTES,
            "report exceeds size limit"
        );
        Captured::from_trivy(&bytes)
    })
    .await??;
    let id = import(
        &Database::connect().await?,
        data,
        &reference,
        &args[1],
        captured,
    )
    .await?;
    println!("{id}");
    Ok(())
}

/// Measures the same compression, object write, staging and commit used by reimport.
/// Keep data generation outside the timed interval.
pub async fn benchmark(data: &Path) -> Result<()> {
    let db = Database::connect().await?;
    let reference = ImageReference::parse("bench.fixture.test/ingest:latest", None)?;
    let instance = Uuid::now_v7();
    let mut samples = Vec::with_capacity(50);
    for sample in 0..55 {
        let findings: Vec<_> = (0..2000)
            .map(|i| {
                serde_json::json!({
                    "VulnerabilityID":format!("BENCH-{instance}-{i}"),
                    "PkgName":format!("bench-pkg-{}",i%400), "InstalledVersion":"1.2.0",
                    "FixedVersion":"1.3.1","Severity": (["HIGH","MEDIUM","LOW","CRITICAL"][i%4]),
                    "Title":"Benchmark finding"
                })
            })
            .collect();
        let packages: Vec<_> = (0..400)
            .map(|i| serde_json::json!({"Name":format!("bench-pkg-{i}"),"Version":"1.2.0"}))
            .collect();
        let report = serde_json::json!({"SchemaVersion":2,"ArtifactType":"container_image",
            "Metadata":{"RepoDigests":[format!("bench.fixture.test/ingest@sha256:{:032x}{:032x}",instance.as_u128(),sample / 2)]},
            "Results":[{"Type":"apk","Packages":packages,"Vulnerabilities":findings}]});
        let bytes = serde_json::to_vec(&report)?;
        let start = std::time::Instant::now();
        let captured = Captured::from_trivy(&bytes)?;
        import(&db, data, &reference, "linux/amd64", captured).await?;
        if sample >= 5 {
            samples.push(start.elapsed().as_secs_f64());
        }
    }
    samples.sort_by(f64::total_cmp);
    let total: f64 = samples.iter().sum();
    println!(
        "50 scans, 2000 findings each, p50 {:.3} ms, p95 {:.3} ms, {:.0} findings/s",
        samples[24] * 1000.0,
        samples[47] * 1000.0,
        100000.0 / total
    );
    Ok(())
}
