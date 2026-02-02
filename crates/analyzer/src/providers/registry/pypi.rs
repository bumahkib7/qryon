//! PyPI version source for Python packages

use super::{VersionInfo, VersionSource, VersionSourceConfig};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use tracing::{debug, warn};

/// Version source for PyPI (Python Package Index)
pub struct PyPiVersionSource {
    config: VersionSourceConfig,
    client: reqwest::blocking::Client,
}

#[derive(Debug, Deserialize)]
struct PyPiResponse {
    releases: HashMap<String, Vec<PyPiRelease>>,
}

#[derive(Debug, Deserialize)]
struct PyPiRelease {
    upload_time_iso_8601: Option<String>,
    yanked: Option<bool>,
}

impl PyPiVersionSource {
    /// Create a new PyPI version source
    pub fn new(config: VersionSourceConfig) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .user_agent("rma-analyzer/0.12.0")
            .build()
            .unwrap_or_default();

        Self { config, client }
    }

    fn cache_path(&self, package: &str) -> PathBuf {
        self.config
            .cache_dir
            .join("pypi")
            .join(format!("{}.json", package.replace('/', "_")))
    }

    fn get_cached(&self, package: &str) -> Option<Vec<VersionInfo>> {
        let cache_path = self.cache_path(package);
        if !cache_path.exists() {
            return None;
        }

        if let Ok(metadata) = fs::metadata(&cache_path)
            && let Ok(modified) = metadata.modified()
            && let Ok(elapsed) = SystemTime::now().duration_since(modified)
            && elapsed > self.config.cache_ttl
        {
            return None;
        }

        fs::read_to_string(&cache_path)
            .ok()
            .and_then(|content| serde_json::from_str(&content).ok())
    }

    fn set_cached(&self, package: &str, versions: &[VersionInfo]) -> Result<()> {
        let cache_path = self.cache_path(package);
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string(versions)?;
        fs::write(cache_path, content)?;
        Ok(())
    }

    fn fetch_versions(&self, package: &str) -> Result<Vec<VersionInfo>> {
        let url = format!("https://pypi.org/pypi/{}/json", package);
        debug!("Fetching PyPI versions from {}", url);

        let response: PyPiResponse = self
            .client
            .get(&url)
            .send()
            .context("Failed to fetch from PyPI")?
            .json()
            .context("Failed to parse PyPI response")?;

        let versions: Vec<VersionInfo> = response
            .releases
            .into_iter()
            .filter_map(|(version, releases)| {
                // Skip empty releases
                if releases.is_empty() {
                    return None;
                }

                let first_release = releases.first()?;
                let yanked = first_release.yanked.unwrap_or(false);

                Some(VersionInfo {
                    version: version.clone(),
                    yanked,
                    prerelease: VersionInfo::is_prerelease_version(&version)
                        || version.contains("a")
                        || version.contains("b")
                        || version.contains("rc"),
                    published_at: first_release.upload_time_iso_8601.clone(),
                    downloads: None,
                })
            })
            .collect();

        Ok(versions)
    }
}

impl VersionSource for PyPiVersionSource {
    fn ecosystem(&self) -> &'static str {
        "PyPI"
    }

    fn list_versions(&self, package: &str) -> Result<Vec<VersionInfo>> {
        if let Some(cached) = self.get_cached(package) {
            debug!("Using cached PyPI versions for {}", package);
            return Ok(cached);
        }

        if self.config.offline {
            anyhow::bail!("No cached data for {} in offline mode", package);
        }

        let versions = self.fetch_versions(package)?;

        if let Err(e) = self.set_cached(package, &versions) {
            warn!("Failed to cache PyPI versions for {}: {}", package, e);
        }

        Ok(versions)
    }

    fn is_available(&self) -> bool {
        !self.config.offline || self.config.cache_dir.exists()
    }
}

#[cfg(test)]
mod tests {
    use super::VersionInfo;

    #[test]
    fn test_pypi_prerelease_detection() {
        assert!(VersionInfo::is_prerelease_version("1.0.0a1"));
        assert!(VersionInfo::is_prerelease_version("1.0.0b2"));
        assert!(VersionInfo::is_prerelease_version("1.0.0rc1"));
        assert!(VersionInfo::is_prerelease_version("2.0.0-alpha"));
        assert!(!VersionInfo::is_prerelease_version("1.0.0"));
    }
}
