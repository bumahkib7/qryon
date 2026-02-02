//! Crates.io version source for Rust packages

use super::{VersionInfo, VersionSource, VersionSourceConfig};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use tracing::{debug, warn};

/// Version source for crates.io (Rust packages)
pub struct CratesIoVersionSource {
    config: VersionSourceConfig,
    client: reqwest::blocking::Client,
}

#[derive(Debug, Deserialize)]
struct CratesIoResponse {
    versions: Vec<CratesIoVersion>,
}

#[derive(Debug, Deserialize)]
struct CratesIoVersion {
    num: String,
    yanked: bool,
    created_at: Option<String>,
    downloads: Option<u64>,
}

impl CratesIoVersionSource {
    /// Create a new crates.io version source
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
            .join("crates.io")
            .join(format!("{}.json", package.replace('/', "_")))
    }

    fn get_cached(&self, package: &str) -> Option<Vec<VersionInfo>> {
        let cache_path = self.cache_path(package);
        if !cache_path.exists() {
            return None;
        }

        // Check cache age
        if let Ok(metadata) = fs::metadata(&cache_path)
            && let Ok(modified) = metadata.modified()
            && let Ok(elapsed) = SystemTime::now().duration_since(modified)
            && elapsed > self.config.cache_ttl
        {
            debug!("Cache expired for {}", package);
            return None;
        }

        match fs::read_to_string(&cache_path) {
            Ok(content) => serde_json::from_str(&content).ok(),
            Err(_) => None,
        }
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
        let url = format!("https://crates.io/api/v1/crates/{}/versions", package);
        debug!("Fetching versions from {}", url);

        let response: CratesIoResponse = self
            .client
            .get(&url)
            .send()
            .context("Failed to fetch from crates.io")?
            .json()
            .context("Failed to parse crates.io response")?;

        let versions: Vec<VersionInfo> = response
            .versions
            .into_iter()
            .map(|v| VersionInfo {
                version: v.num.clone(),
                yanked: v.yanked,
                prerelease: VersionInfo::is_prerelease_version(&v.num),
                published_at: v.created_at,
                downloads: v.downloads,
            })
            .collect();

        Ok(versions)
    }
}

impl VersionSource for CratesIoVersionSource {
    fn ecosystem(&self) -> &'static str {
        "crates.io"
    }

    fn list_versions(&self, package: &str) -> Result<Vec<VersionInfo>> {
        // Check cache first
        if let Some(cached) = self.get_cached(package) {
            debug!(
                "Using cached versions for {} ({} versions)",
                package,
                cached.len()
            );
            return Ok(cached);
        }

        // If offline, fail
        if self.config.offline {
            anyhow::bail!("No cached data for {} in offline mode", package);
        }

        // Fetch from API
        let versions = self.fetch_versions(package)?;

        // Cache the results
        if let Err(e) = self.set_cached(package, &versions) {
            warn!("Failed to cache versions for {}: {}", package, e);
        }

        Ok(versions)
    }

    fn is_available(&self) -> bool {
        !self.config.offline || self.config.cache_dir.exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let v = VersionInfo {
            version: "1.0.0".to_string(),
            yanked: false,
            prerelease: false,
            published_at: None,
            downloads: None,
        };
        assert!(!v.prerelease);
    }
}
