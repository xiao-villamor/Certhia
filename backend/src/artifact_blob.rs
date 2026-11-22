use anyhow::{Result, ensure};
use rusty_s3::S3Action;
use std::{io::Write, path::Path, time::Duration};

pub async fn persist(
    db: &crate::postgres::Database,
    data: &Path,
    hash: &str,
    raw: &[u8],
) -> Result<String> {
    let key = format!("reports/{}/{}.json.zst", &hash[..2], hash);
    let s3 = crate::artifacts::store();
    let reference = format!("{}:{key}", if s3.is_some() { "s3" } else { "file" });
    sqlx::query!("INSERT INTO stored_blobs VALUES($1,now()) ON CONFLICT(object_key) DO UPDATE SET touched_at=now()",reference).execute(&db.primary).await?;
    let target = data.join(&key);
    if s3.is_none() && tokio::fs::try_exists(&target).await? {
        return Ok(reference);
    }
    let bytes = raw.to_vec();
    let compressed =
        tokio::task::spawn_blocking(move || zstd::encode_all(bytes.as_slice(), 3)).await??;
    if let Some((bucket, credentials)) = s3 {
        let url = bucket
            .put_object(Some(&credentials), &key)
            .sign(Duration::from_secs(90));
        let response = crate::artifacts::client()?
            .put(url)
            .body(compressed)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("artifact upload failed"))?;
        ensure!(
            response.status().is_success(),
            "artifact store rejected upload"
        );
        return Ok(format!("s3:{key}"));
    }

    tokio::task::spawn_blocking(move || -> Result<()> {
        let parent = target.parent().expect("report has parent");
        std::fs::create_dir_all(parent)?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        tmp.write_all(&compressed)?;
        tmp.as_file().sync_all()?;
        tmp.persist(&target)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })
    .await??;
    Ok(format!("file:{key}"))
}

pub async fn retrieve(data: &Path, object: &str) -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    let (storage, key) = object
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid artifact reference"))?;
    ensure!(
        key.starts_with("reports/")
            && key
                .split('/')
                .all(|part| !part.is_empty() && part != ".." && part != "."),
        "Invalid artifact key"
    );
    let packed = match storage {
        "file" => match tokio::fs::read(data.join(key)).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        },
        "s3" => match crate::artifacts::read(key).await? {
            Some(bytes) => bytes,
            None => return Ok(None),
        },
        _ => anyhow::bail!("Unknown report store"),
    };
    let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut out = Vec::new();
        zstd::Decoder::new(packed.as_slice())?
            .take(crate::scanner::MAX_REPORT_BYTES as u64 + 1)
            .read_to_end(&mut out)?;
        ensure!(
            out.len() <= crate::scanner::MAX_REPORT_BYTES,
            "Report size exceeded"
        );
        Ok(out)
    })
    .await??;
    Ok(Some(bytes))
}

pub async fn collect(app: &crate::App, remove_s3: bool) -> Result<()> {
    let mut tx = app.0.database.primary.begin().await?;
    sqlx::query!("DELETE FROM artifact_refs a USING scan_directory d WHERE d.id=a.scan_id AND NOT EXISTS(SELECT FROM scans WHERE (id,queued_at)=(d.id,d.queued_at))").execute(&mut *tx).await?;
    let orphans=sqlx::query_scalar!("SELECT object_key FROM stored_blobs b WHERE touched_at<now()-interval '1 day' AND ($1 OR b.object_key LIKE 'file:%')
        AND NOT EXISTS(SELECT FROM scans WHERE raw_report_ref=b.object_key)
        AND NOT EXISTS(SELECT FROM artifact_refs a WHERE a.object_key=b.object_key AND a.owned)
        ORDER BY touched_at,object_key LIMIT 20 FOR UPDATE SKIP LOCKED",remove_s3).fetch_all(&mut *tx).await?;
    for object in orphans {
        if let Some(key) = object.strip_prefix("file:reports/") {
            ensure!(
                key.split('/')
                    .all(|p| !p.is_empty() && p != "." && p != ".."),
                "Invalid report key"
            );
            if let Err(e) = tokio::fs::remove_file(app.0.data.join("reports").join(key)).await
                && e.kind() != std::io::ErrorKind::NotFound
            {
                return Err(e.into());
            }
        } else if let Some(key) = object.strip_prefix("s3:") {
            let Some((bucket, creds)) = crate::artifacts::store() else {
                continue;
            };
            let url = bucket
                .delete_object(Some(&creds), key)
                .sign(Duration::from_secs(90));
            let res = crate::artifacts::client()?
                .delete(url)
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("Artifact delete failed"))?;
            ensure!(
                res.status().is_success() || res.status() == reqwest::StatusCode::NOT_FOUND,
                "Artifact delete rejected"
            );
        }
        sqlx::query!("DELETE FROM stored_blobs WHERE object_key=$1", object)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
