//! Go proxy version source for Go modules

use super::{VersionInfo, VersionSource, VersionSourceConfig};
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;
use tracing::{debug, warn};

/// Version source for Go modules via proxy.golang.org
pub struct GoVersionSource {
    config: VersionSourceConfig,
    client: reqwest::blocking::Client,
}

impl GoVersionSource {
    /// Create a new Go version source
    pub fn new(config: VersionSourceConfig) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .user_agent("rma-analyzer/0.12.0")
            .build()
            .unwrap_or_default();

        Self { config, client }
    }

    fn cache_path(&self, module: &str) -> PathBuf {
        self.config
            .cache_dir
            .join("go")
            .join(format!("{}.json", module.replace('/', "_")))
    }

    fn get_cached(&self, module: &str) -> Option<Vec<VersionInfo>> {
        let cache_path = self.cache_path(module);
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

    fn set_cached(&self, module: &str, versions: &[VersionInfo]) -> Result<()> {
        let cache_path = self.cache_path(module);
        if let Some(parent) = cache_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string(versions)?;
        fs::write(cache_path, content)?;
        Ok(())
    }

    fn fetch_versions(&self, module: &str) -> Result<Vec<VersionInfo>> {
        // Go proxy uses case-insensitive encoding for module paths
        let encoded_module = module
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    format!("!{}", c.to_ascii_lowercase())
                } else {
                    c.to_string()
                }
            })
            .collect::<String>();

        let url = format!("https://proxy.golang.org/{}/@v/list", encoded_module);
        debug!("Fetching Go versions from {}", url);

        let response = self
            .client
            .get(&url)
            .send()
            .context("Failed to fetch from Go proxy")?
            .text()
            .context("Failed to read Go proxy response")?;

        let versions: Vec<VersionInfo> = response
            .lines()
            .filter(|line| !line.is_empty())
            .map(|version| {
                let version = version.trim().to_string();
                VersionInfo {
                    yanked: false, // Go modules don't have yanked concept (retracted instead)
                    prerelease: VersionInfo::is_prerelease_version(&version)
                        || version.contains("-pre")
                        || version.contains("-rc"),
                    published_at: None,
                    downloads: None,
                    version,
                }
            })
            .collect();

        Ok(versions)
    }
}

impl VersionSource for GoVersionSource {
    fn ecosystem(&self) -> &'static str {
        "Go"
    }

    fn list_versions(&self, module: &str) -> Result<Vec<VersionInfo>> {
        if let Some(cached) = self.get_cached(module) {
            debug!("Using cached Go versions for {}", module);
            return Ok(cached);
        }

        if self.config.offline {
            anyhow::bail!("No cached data for {} in offline mode", module);
        }

        let versions = self.fetch_versions(module)?;

        if let Err(e) = self.set_cached(module, &versions) {
            warn!("Failed to cache Go versions for {}: {}", module, e);
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
    fn test_module_encoding() {
        let module = "github.com/Azure/azure-sdk-for-go";
        let encoded: String = module
            .chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    format!("!{}", c.to_ascii_lowercase())
                } else {
                    c.to_string()
                }
            })
            .collect();
        assert_eq!(encoded, "github.com/!azure/azure-sdk-for-go");
    }
}
