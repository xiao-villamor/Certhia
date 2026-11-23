use crate::{
    domain::{Captured, ImageReference},
    jobs::Activity,
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Map, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{ExitStatus, Output, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Command,
};

pub const MAX_REPORT_BYTES: usize = 20 * 1024 * 1024;

pub fn binary(tool: &str) -> &str {
    match tool {
        "osv" => "osv-scanner",
        name => name,
    }
}

pub fn installed(tool: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| {
            dir.join(binary(tool))
                .metadata()
                .is_ok_and(|info| info.is_file() && info.permissions().mode() & 0o111 != 0)
        })
    })
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

pub struct Vault(Aes256Gcm);

impl Vault {
    pub fn open(file: &Path) -> Result<Self> {
        if file.exists() {
            return Self::from_file(file);
        }
        let parent = file.parent().context("Key directory missing")?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        let mut key = [0; 32];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| anyhow::anyhow!("System random source unavailable"))?;
        tmp.write_all(&key)?;
        tmp.as_file().sync_all()?;
        match tmp.persist_noclobber(file) {
            Ok(_) => {
                fs::File::open(parent)?.sync_all()?;
                Self::from_bytes(&key)
            }
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => Self::from_file(file),
            Err(e) => Err(e.error.into()),
        }
    }
    pub fn from_file(file: &Path) -> Result<Self> {
        Self::from_bytes(&fs::read(file)?)
    }

    fn from_bytes(key: &[u8]) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| anyhow!("Registry key file must contain 32 bytes"))?;
        Ok(Self(cipher))
    }

    pub fn seal(&self, host: &str, credentials: &Credentials) -> Result<Vec<u8>> {
        self.seal_bytes(host, &serde_json::to_vec(credentials)?)
    }

    pub(crate) fn seal_bytes(&self, purpose: &str, secret: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| anyhow::anyhow!("System random source unavailable"))?;
        let encrypted = self
            .0
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: secret,
                    aad: purpose.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("Could not encrypt credentials."))?;
        Ok([nonce.to_vec(), encrypted].concat())
    }

    pub fn open_secret(&self, host: &str, secret: &[u8]) -> Result<Credentials> {
        Ok(serde_json::from_slice(&self.open_bytes(host, secret)?)?)
    }

    pub(crate) fn open_bytes(&self, purpose: &str, secret: &[u8]) -> Result<Vec<u8>> {
        if secret.len() < 28 {
            bail!("Saved credentials could not be read.");
        }
        let (nonce, encrypted) = secret.split_at(12);
        let bytes = self
            .0
            .decrypt(
                nonce
                    .try_into()
                    .map_err(|_| anyhow!("Invalid saved nonce"))?,
                Payload {
                    msg: encrypted,
                    aad: purpose.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("Saved credentials could not be read."))?;
        Ok(bytes)
    }
}

pub(crate) fn docker_config(
    path: &Path,
    host: &str,
    credentials: Option<Credentials>,
) -> Result<()> {
    let mut hosts = Map::new();
    if let Some(credentials) = credentials {
        let encoded = STANDARD.encode(format!("{}:{}", credentials.username, credentials.password));
        let auth = json!({ "auth": encoded });
        hosts.insert(host.to_owned(), auth.clone());
        if host == "docker.io" {
            hosts.insert("https://index.docker.io/v1/".to_owned(), auth.clone());
            hosts.insert("registry-1.docker.io".to_owned(), auth);
        }
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec(&json!({ "auths": hosts }))?)?;
    Ok(())
}

pub(crate) async fn run(mut command: Command, binary: &str, timeout: Duration) -> Result<Output> {
    command.kill_on_drop(true);
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| anyhow!("{binary} timed out."))?;
    let output = output.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow!("{binary} is missing from this installation.")
        } else {
            anyhow!("Could not run {binary}.")
        }
    })?;
    check_exit(output.status, &output.stderr, binary)?;
    Ok(output)
}

fn check_exit(status: ExitStatus, stderr: &[u8], binary: &str) -> Result<()> {
    if !status.success() {
        let reason = String::from_utf8_lossy(stderr).to_lowercase();
        if ["unauthorized", "authentication", "denied", "401", "403"]
            .iter()
            .any(|text| reason.contains(text))
        {
            bail!("Registry access denied. Verify the username and token have pull access.");
        }
        if ["manifest unknown", "name unknown", "manifest_unknown"]
            .iter()
            .any(|text| reason.contains(text))
        {
            bail!("The registry could not find that image tag or digest.");
        }
        if reason.contains("x509") || reason.contains("certificate") {
            bail!("The registry TLS certificate could not be verified.");
        }
        if reason.contains("db") && reason.contains("download") {
            bail!("Trivy could not download its vulnerability database.");
        }
        if reason.contains("lookup")
            || reason.contains("connection refused")
            || reason.contains("timeout")
        {
            bail!("The registry or a scanner dependency is unreachable.");
        }
        bail!("{binary} could not read this image. Check the reference and platform.");
    }
    Ok(())
}

pub async fn observe<F: Future<Output = ()> + Send>(
    mut command: Command,
    binary: &str,
    mut line: impl FnMut(String) -> F + Send,
) -> Result<(ExitStatus, Vec<u8>)> {
    tokio::time::timeout(scan_timeout(), async {
        let mut child = command
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    anyhow!("{binary} is missing from this installation.")
                } else {
                    anyhow!("Could not run {binary}.")
                }
            })?;
        let mut logs = BufReader::new(
            child
                .stderr
                .take()
                .context("Could not connect to scanner output.")?,
        );
        let mut recent = Vec::with_capacity(8192);
        let mut buffer = Vec::with_capacity(4096);
        while (&mut logs)
            .take(4096)
            .read_until(b'\n', &mut buffer)
            .await?
            != 0
        {
            line(String::from_utf8_lossy(&buffer).into_owned()).await;
            if recent.len() + buffer.len() > 8192 {
                recent.drain(..recent.len() + buffer.len() - 8192);
            }
            recent.extend_from_slice(&buffer);
            buffer.clear();
        }
        Ok((child.wait().await?, recent))
    })
    .await
    .map_err(|_| anyhow!("{binary} timed out."))?
}

fn trivy_step(line: &str) -> Option<(&'static str, &'static str, &'static str)> {
    let mut fields = line.splitn(3, '\t');
    let _timestamp = fields.next()?;
    let level = fields.next()?;
    if level.trim() != "INFO" {
        return None;
    }
    let message = fields.next()?.trim();
    if message.starts_with("[vulndb] Downloading vulnerability DB")
        || message.starts_with("[vulndb] Need to update DB")
    {
        Some((
            "vulnerability_db",
            "Updating vulnerability database",
            "Trivy is fetching the advisory database it uses to match known vulnerabilities.",
        ))
    } else if message.starts_with("[javadb] Downloading")
        || message.starts_with("[javadb] Need to update")
    {
        Some((
            "java_db",
            "Updating Java database",
            "Trivy is fetching metadata to identify Java dependencies.",
        ))
    } else if message.starts_with("Detected OS") {
        Some((
            "os_detected",
            "Detected the operating system",
            "Trivy identified the base distribution and can check its packages.",
        ))
    } else if message.contains("Detecting vulnerabilities...") && message.starts_with('[') {
        Some((
            "vulnerabilities",
            "Checking packages for vulnerabilities",
            "Trivy is matching installed package versions against advisories.",
        ))
    } else if message.starts_with("Number of language-specific files") {
        Some((
            "languages",
            "Checking application dependencies",
            "Trivy finished locating language-specific files in the image.",
        ))
    } else {
        None
    }
}

pub async fn test(
    reference: &ImageReference,
    credentials: Option<Credentials>,
    insecure: bool,
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config = directory.path().join("config.json");
    let credentials = crate::registries::pull_credentials(&reference.host, credentials).await?;
    docker_config(&config, &reference.host, credentials)?;
    let mut command = Command::new("skopeo");
    command
        .arg("inspect")
        .arg("--raw")
        .arg("--authfile")
        .arg(config);
    if insecure {
        command.arg("--tls-verify=false");
    }
    command.arg(format!("docker://{}", reference.value));
    let output = run(command, "Skopeo", Duration::from_secs(30)).await?;
    let manifest: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("The registry did not return an image manifest.")?;
    if manifest["schemaVersion"] != 2 {
        bail!("The registry did not return a supported image manifest.");
    }
    Ok(())
}

pub enum Target<'a> {
    Remote(&'a ImageReference, bool),
    Docker(&'a str),
    Archive(&'a Path),
}

pub async fn scan(
    target: Target<'_>,
    platform: &str,
    credentials: Option<Credentials>,
    cache: &Path,
    activity: Activity<'_>,
) -> Result<Captured> {
    let directory = tempfile::tempdir()?;
    let host = match &target {
        Target::Remote(reference, _) => reference.host.as_str(),
        _ => "",
    };
    let credentials = crate::registries::pull_credentials(host, credentials).await?;
    docker_config(&directory.path().join("config.json"), host, credentials)?;
    let output = directory.path().join("report.json");
    let mut command = Command::new("trivy");
    command
        .env("DOCKER_CONFIG", directory.path())
        .env_remove("TRIVY_USERNAME")
        .env_remove("TRIVY_PASSWORD")
        .env_remove("TRIVY_TOKEN")
        .arg("image")
        .args(["--cache-backend", "memory"])
        .arg("--cache-dir")
        .arg(cache)
        .args(["--no-progress", "--skip-version-check"])
        .args([
            "--scanners",
            "vuln,misconfig,secret,license",
            "--image-config-scanners",
            "misconfig,secret",
            "--list-all-pkgs",
            "--format",
            "json",
            "--parallel",
            "2",
        ])
        .arg("--platform")
        .arg(platform)
        .arg("--output")
        .arg(&output);
    match target {
        Target::Remote(reference, insecure) => {
            activity
                .record(
                    "image",
                    "Reading registry image",
                    "Trivy is retrieving the image metadata and layers for the selected platform.",
                )
                .await;
            if insecure {
                command.arg("--insecure");
            }
            command
                .args(["--image-src", "remote", "--"])
                .arg(&reference.value);
        }
        Target::Docker(reference) => {
            activity
                .record(
                    "image",
                    "Reading local Docker image",
                    "Trivy is opening the image through the local Docker engine.",
                )
                .await;
            let socket = std::env::var("CERTHIA_DOCKER_SOCKET")
                .context("Docker discovery is not configured.")?;
            command
                .env("DOCKER_HOST", format!("unix://{socket}"))
                .args(["--image-src", "docker", "--"])
                .arg(reference);
        }
        Target::Archive(path) => {
            activity
                .record(
                    "image",
                    "Reading image archive",
                    "Trivy is opening the uploaded archive and its layers.",
                )
                .await;
            command.arg("--input").arg(path);
        }
    }
    activity
        .record(
            "trivy",
            "Running Trivy",
            "Checking packages, image configuration, secrets, and licenses.",
        )
        .await;
    let (status, stderr) = observe(command, "Trivy", |line| async move {
        if let Some((step, title, detail)) = trivy_step(&line) {
            activity.record(step, title, detail).await;
        }
    })
    .await?;
    check_exit(status, &stderr, "Trivy")?;
    activity
        .record(
            "normalize",
            "Preparing the report",
            "Reading Trivy results and organizing packages and findings.",
        )
        .await;
    if tokio::fs::metadata(&output).await?.len() > MAX_REPORT_BYTES as u64 {
        bail!("The scanner report exceeds the 20 MB limit.");
    }
    let mut captured = Captured::from_trivy(&tokio::fs::read(output).await?)?;
    crate::artifacts::record_trivy(&mut captured);
    Ok(captured)
}

pub fn scan_timeout() -> Duration {
    let minutes = std::env::var("CERTHIA_SCAN_TIMEOUT_MINUTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(1, 180);
    Duration::from_secs(minutes * 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trivy_activity_uses_known_messages_without_exposing_log_values() {
        let database = "2026-11-20T11:00:00Z\tINFO\t[vulndb] Downloading vulnerability DB...\trepository=private-token";
        assert_eq!(trivy_step(database).unwrap().0, "vulnerability_db");
        assert!(!trivy_step(database).unwrap().2.contains("private-token"));
        assert_eq!(
            trivy_step("date\tINFO\tDetected OS\tfamily=alpine")
                .unwrap()
                .0,
            "os_detected"
        );
        assert!(trivy_step("date\tWARN\tprivate registry rejected token").is_none());
        assert!(trivy_step("date\tINFO\t[secret] Secret scanning is enabled").is_none());
    }

    #[test]
    fn saved_credentials_are_bound_to_the_registry_and_survive_restart() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let file = directory.path().join("key");
        let vault = Vault::open(&file)?;
        let credentials = Credentials {
            username: "reader".into(),
            password: "secret".into(),
        };
        let encrypted = vault.seal("registry.example", &credentials)?;
        assert!(!encrypted.windows(6).any(|part| part == b"secret"));
        let vault = Vault::open(&file)?;
        assert_eq!(
            vault.open_secret("registry.example", &encrypted)?.password,
            "secret"
        );
        assert!(vault.open_secret("other.example", &encrypted).is_err());
        Ok(())
    }
}
