use super::{Source, copy};
use crate::jobs::Activity;
use anyhow::{Result, anyhow};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    fs::{self, File, TryLockError},
    io::{self, ErrorKind},
    path::Path,
    time::{Duration, SystemTime},
};

const MAX_CACHE_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const MAX_CACHE_ARCHIVES: usize = 64;

pub(crate) async fn prepare(
    directory: &Path,
    staged: &Path,
    registry_id: Option<&str>,
    source: Source,
    activity: Activity<'_>,
) -> Result<()> {
    tokio::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .await?;
    let key = cache_key(&source, registry_id);
    let cached = directory.join(format!("{key}.tar"));
    // Share locks across worker processes. Use a fixed set of lock files so
    // their number stays bounded as tags move to new digests.
    let lock = open_lock(&directory.join(format!("{}.lock", &key[..2]))).await?;
    if !try_lock(&lock)? {
        activity
            .record(
                "image_cache_wait",
                "Waiting for the local image cache",
                "Another scan is preparing an archive.",
            )
            .await;
        wait_for_lock(&lock).await?;
    }
    if restore(&cached, staged).await? {
        activity
            .record(
                "image_cached",
                "Reusing cached image",
                "The local archive matches the current registry digest.",
            )
            .await;
        return Ok(());
    }

    activity
        .record(
            "image_download",
            "Downloading image layers",
            "Fetching layers from the registry and writing the local scan archive.",
        )
        .await;
    let platform = source.platform.clone();
    copy(
        source,
        &format!("docker-archive:{}:certhia:scan", staged.display()),
        "",
        None,
        false,
    )
    .await
    .map_err(|error| {
        anyhow!("Could not download and prepare image layers for {platform}. {error}")
    })?;
    activity
        .record(
            "image_ready",
            "Image download complete",
            "The local archive is ready for scanning.",
        )
        .await;

    let directory = directory.to_owned();
    let staged = staged.to_owned();
    let result = async {
        let budget = open_lock(&directory.join("budget.lock")).await?;
        wait_for_lock(&budget).await?;
        tokio::task::spawn_blocking(move || {
            let (_download_lock, _budget_lock) = (lock, budget);
            remember(&directory, &cached, &staged, MAX_CACHE_BYTES)
        })
        .await??;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        tracing::warn!(%error, "Could not retain the registry image archive");
    }
    Ok(())
}

fn cache_key(source: &Source, registry_id: Option<&str>) -> String {
    let mut hash = Sha256::new();
    for part in [
        source.reference.as_str(),
        source.platform.as_str(),
        registry_id.unwrap_or_default(),
    ] {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    hash.update([u8::from(source.insecure)]);
    let mut key = String::with_capacity(64);
    for byte in hash.finalize() {
        write!(key, "{byte:02x}").expect("infallible write to String");
    }
    key
}

async fn open_lock(path: &Path) -> io::Result<File> {
    Ok(tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .await?
        .into_std()
        .await)
}

fn try_lock(file: &File) -> io::Result<bool> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(TryLockError::WouldBlock) => Ok(false),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

async fn wait_for_lock(file: &File) -> io::Result<()> {
    while !try_lock(file)? {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}

async fn restore(cached: &Path, staged: &Path) -> io::Result<bool> {
    match tokio::fs::hard_link(cached, staged).await {
        Ok(()) => {
            // The per-scan link keeps the archive available even if the cache evicts it.
            if let Ok(file) = tokio::fs::File::open(staged).await {
                let _ = file.into_std().await.set_modified(SystemTime::now());
            }
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn remember(directory: &Path, cached: &Path, staged: &Path, max_bytes: u64) -> io::Result<()> {
    let size = fs::metadata(staged)?.len();
    if size > max_bytes {
        return Ok(());
    }
    let mut entries = Vec::new();
    let mut total = size;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "tar") {
            let metadata = fs::metadata(&path)?;
            total = total.saturating_add(metadata.len());
            entries.push((metadata.modified()?, path, metadata.len()));
        }
    }
    let mut count = entries.len() + 1;
    if total > max_bytes || count > MAX_CACHE_ARCHIVES {
        entries.sort_unstable();
        for (_, path, size) in entries {
            fs::remove_file(path)?;
            total -= size;
            count -= 1;
            if total <= max_bytes && count <= MAX_CACHE_ARCHIVES {
                break;
            }
        }
    }
    fs::hard_link(staged, cached)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn eviction_keeps_archives_open_to_active_scans() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let first = dir.path().join("first.tar");
        let second = dir.path().join("second.tar");
        let staged = dir.path().join("staged");
        let reused = dir.path().join("reused");
        assert!(!restore(&first, &reused).await?);
        fs::write(&staged, b"first")?;
        remember(dir.path(), &first, &staged, 6)?;
        fs::remove_file(&staged)?;
        assert!(restore(&first, &reused).await?);
        fs::write(&staged, b"second")?;
        remember(dir.path(), &second, &staged, 6)?;
        assert!(!first.exists());
        assert_eq!(fs::read(reused)?, b"first");
        assert_eq!(fs::read(second)?, b"second");
        Ok(())
    }
}
