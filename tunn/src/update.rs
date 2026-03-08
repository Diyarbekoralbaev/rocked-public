//! Version checking and self-update for the tunn CLI.

use serde::Deserialize;
use tracing::debug;

const GITHUB_REPO: &str = "Diyarbekoralbaev/tunn";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

// ── GitHub API types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

// ── Semver comparison ───────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version(u32, u32, u32);

fn parse_version(s: &str) -> Option<Version> {
    let s = s.strip_prefix('v').unwrap_or(s);
    let mut parts = s.splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some(Version(major, minor, patch))
}

fn is_newer(remote: &str, local: &str) -> bool {
    match (parse_version(remote), parse_version(local)) {
        (Some(r), Some(l)) => r > l,
        _ => false,
    }
}

// ── Background version check ────────────────────────────────────────

/// Spawn a non-blocking background task that prints a notification
/// to stderr if a newer version is available on GitHub.
pub fn spawn_version_check() {
    tokio::spawn(async {
        let result = tokio::time::timeout(CHECK_TIMEOUT, check_latest()).await;
        match result {
            Ok(Ok(tag)) if is_newer(&tag, CURRENT_VERSION) => {
                let v = tag.strip_prefix('v').unwrap_or(&tag);
                // Small delay so tunnel info line prints first.
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                eprintln!();
                eprintln!("  Update available: v{CURRENT_VERSION} \u{2192} v{v}");
                eprintln!("  Run `tunn update` to upgrade.");
                eprintln!();
            }
            Ok(Err(e)) => debug!("version check failed: {e}"),
            Err(_) => debug!("version check timed out"),
            _ => {}
        }
    });
}

async fn check_latest() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Use redirect-based approach to avoid GitHub API rate limits.
    // GET /releases/latest returns 302 → .../tag/v0.2.0
    let url = format!("https://github.com/{GITHUB_REPO}/releases/latest");
    let client = reqwest::Client::builder()
        .user_agent(format!("tunn/{CURRENT_VERSION}"))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let resp = client.get(&url).send().await?;
    let location = resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .ok_or("no redirect from /releases/latest")?;
    let tag = location
        .rsplit('/')
        .next()
        .ok_or("cannot parse tag from redirect URL")?;
    Ok(tag.to_string())
}

// ── Self-update command ─────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no binary found for {os}/{arch}")]
    NoArtifact { os: String, arch: String },
    #[error("already up to date (v{0})")]
    AlreadyUpToDate(String),
    #[error("download size mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("{0}")]
    Other(String),
}

/// Run the interactive self-update: check → download → replace binary.
pub async fn run_update() -> Result<(), UpdateError> {
    eprintln!("tunn v{CURRENT_VERSION} \u{2014} checking for updates...");

    let client = reqwest::Client::builder()
        .user_agent(format!("tunn/{CURRENT_VERSION}"))
        .build()?;

    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let resp = client.get(&url).send().await?;
    if resp.status() == 403 || resp.status() == 429 {
        return Err(UpdateError::Other(
            "GitHub API rate limit exceeded, try again later".into(),
        ));
    }
    let release: GithubRelease = resp.json().await?;

    if !is_newer(&release.tag_name, CURRENT_VERSION) {
        return Err(UpdateError::AlreadyUpToDate(CURRENT_VERSION.to_string()));
    }

    let new_version = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);

    let name = artifact_name()?;
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| UpdateError::NoArtifact {
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
        })?;

    eprintln!("downloading {name}...");

    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await?
        .bytes()
        .await?;

    if bytes.len() as u64 != asset.size {
        return Err(UpdateError::SizeMismatch {
            expected: asset.size,
            actual: bytes.len() as u64,
        });
    }

    let current_exe = std::env::current_exe()
        .map_err(|e| UpdateError::Other(format!("cannot locate current binary: {e}")))?;

    replace_binary(&current_exe, &bytes)?;

    eprintln!("updated: v{CURRENT_VERSION} \u{2192} v{new_version}");
    Ok(())
}

fn artifact_name() -> Result<String, UpdateError> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => {
            return Err(UpdateError::NoArtifact {
                os: other.into(),
                arch: std::env::consts::ARCH.into(),
            })
        }
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => {
            return Err(UpdateError::NoArtifact {
                os: std::env::consts::OS.into(),
                arch: other.into(),
            })
        }
    };
    let ext = if cfg!(windows) { ".exe" } else { "" };
    Ok(format!("tunn-{os}-{arch}{ext}"))
}

fn replace_binary(target: &std::path::Path, new_bytes: &[u8]) -> Result<(), UpdateError> {
    let parent = target
        .parent()
        .ok_or_else(|| UpdateError::Other("cannot determine binary directory".into()))?;

    if cfg!(unix) {
        let tmp = parent.join(".tunn.update.tmp");
        std::fs::write(&tmp, new_bytes)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        }

        std::fs::rename(&tmp, target)?;
    } else {
        let backup = target.with_extension("exe.old");
        let _ = std::fs::remove_file(&backup);
        std::fs::rename(target, &backup)?;
        if let Err(e) = std::fs::write(target, new_bytes) {
            let _ = std::fs::rename(&backup, target);
            return Err(UpdateError::Io(e));
        }
        let _ = std::fs::remove_file(&backup);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_basic() {
        assert_eq!(parse_version("1.2.3"), Some(Version(1, 2, 3)));
        assert_eq!(parse_version("v0.1.0"), Some(Version(0, 1, 0)));
        assert_eq!(parse_version("v10.20.30"), Some(Version(10, 20, 30)));
        assert_eq!(parse_version("invalid"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn is_newer_works() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("v0.1.1", "0.1.0"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.0.9", "0.1.0"));
        assert!(!is_newer("invalid", "0.1.0"));
    }

    #[test]
    fn artifact_name_current_platform() {
        let name = artifact_name().unwrap();
        assert!(name.starts_with("tunn-"));
        assert!(name.contains("amd64") || name.contains("arm64"));
    }
}
