//! npm registry version source for JavaScript/TypeScript packages

use super::{VersionInfo, VersionSource, VersionSourceConfig};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use tracing::{debug, warn};

/// Version source for npm registry
pub struct NpmVersionSource {
    config: VersionSourceConfig,
    client: reqwest::blocking::Client,
}

#[derive(Debug, Deserialize)]
struct NpmPackageResponse {
    versions: HashMap<String, NpmVersionInfo>,
    time: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct NpmVersionInfo {
    version: String,
    deprecated: Option<String>,
}

impl NpmVersionSource {
    /// Create a new npm version source
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
            .join("npm")
            .join(format!("{}.json", package.replace(['/', '@'], "_")))
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
        // Handle scoped packages (@org/package)
        let encoded = if package.starts_with('@') {
            package.replace('/', "%2F")
        } else {
            package.to_string()
        };

        let url = format!("https://registry.npmjs.org/{}", encoded);
        debug!("Fetching npm versions from {}", url);

        let response: NpmPackageResponse = self
            .client
            .get(&url)
            .send()
            .context("Failed to fetch from npm registry")?
            .json()
            .context("Failed to parse npm response")?;

        let versions: Vec<VersionInfo> = response
            .versions
            .into_iter()
            .map(|(version, info)| {
                let published_at = response
                    .time
                    .as_ref()
                    .and_then(|t| t.get(&version))
                    .cloned();

                VersionInfo {
                    version: version.clone(),
                    yanked: info.deprecated.is_some(),
                    prerelease: VersionInfo::is_prerelease_version(&version),
                    published_at,
                    downloads: None,
                }
            })
            .collect();

        Ok(versions)
    }
}

impl VersionSource for NpmVersionSource {
    fn ecosystem(&self) -> &'static str {
        "npm"
    }

    fn list_versions(&self, package: &str) -> Result<Vec<VersionInfo>> {
        if let Some(cached) = self.get_cached(package) {
            debug!("Using cached npm versions for {}", package);
            return Ok(cached);
        }

        if self.config.offline {
            anyhow::bail!("No cached data for {} in offline mode", package);
        }

        let versions = self.fetch_versions(package)?;

        if let Err(e) = self.set_cached(package, &versions) {
            warn!("Failed to cache npm versions for {}: {}", package, e);
        }

        Ok(versions)
    }

    fn is_available(&self) -> bool {
        !self.config.offline || self.config.cache_dir.exists()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_scoped_package_encoding() {
        let package = "@types/node";
        let encoded = if package.starts_with('@') {
            package.replace('/', "%2F")
        } else {
            package.to_string()
        };
        assert_eq!(encoded, "@types%2Fnode");
    }
}
