//! Registry version discovery for package ecosystems
//!
//! This module provides version discovery from package registries for use in
//! vulnerability fix planning. Each ecosystem has its own implementation.

mod crates_io;
mod go;
mod npm;
mod pypi;

pub use crates_io::CratesIoVersionSource;
pub use go::GoVersionSource;
pub use npm::NpmVersionSource;
pub use pypi::PyPiVersionSource;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Information about a package version from a registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// The version string (e.g., "1.2.3")
    pub version: String,
    /// Whether this version has been yanked/deprecated
    pub yanked: bool,
    /// Whether this is a prerelease version
    pub prerelease: bool,
    /// Publication timestamp (ISO 8601 format)
    pub published_at: Option<String>,
    /// Download count if available (for popularity scoring)
    pub downloads: Option<u64>,
}

impl VersionInfo {
    /// Check if version is a prerelease based on version string
    pub fn is_prerelease_version(version: &str) -> bool {
        // Common prerelease indicators
        let lower = version.to_lowercase();
        lower.contains("-alpha")
            || lower.contains("-beta")
            || lower.contains("-rc")
            || lower.contains("-pre")
            || lower.contains("-dev")
            || lower.contains("-snapshot")
            || lower.contains("-canary")
            || lower.contains("-next")
            || lower.contains("-nightly")
            // Check for semver prerelease: X.Y.Z-something
            || version.contains('-')
            // Python-style prereleases: 1.0.0a1, 1.0.0b2, 1.0.0rc1
            || regex::Regex::new(r"\d+\.\d+\.\d+[ab]\d+$").is_ok_and(|re| re.is_match(version))
            || regex::Regex::new(r"\d+\.\d+\.\d+rc\d+$").is_ok_and(|re| re.is_match(version))
    }
}

/// Trait for fetching available versions from a package registry
pub trait VersionSource: Send + Sync {
    /// Get the ecosystem name (e.g., "crates.io", "npm")
    fn ecosystem(&self) -> &'static str;

    /// List all available versions for a package
    fn list_versions(&self, package: &str) -> Result<Vec<VersionInfo>>;

    /// Check if the source is available (has network access, etc.)
    fn is_available(&self) -> bool;
}

/// Configuration for version sources
#[derive(Debug, Clone)]
pub struct VersionSourceConfig {
    /// Cache directory for responses
    pub cache_dir: PathBuf,
    /// Cache TTL duration
    pub cache_ttl: Duration,
    /// Whether to operate in offline mode (cache only)
    pub offline: bool,
    /// HTTP timeout
    pub timeout: Duration,
}

impl Default for VersionSourceConfig {
    fn default() -> Self {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("rma")
            .join("registry");

        Self {
            cache_dir,
            cache_ttl: Duration::from_secs(3600), // 1 hour
            offline: false,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Semver utilities for version comparison and classification
pub mod semver_utils {
    use std::cmp::Ordering;

    /// Parsed semantic version for comparison
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SemVer {
        pub major: u32,
        pub minor: u32,
        pub patch: u32,
        pub prerelease: Option<String>,
        pub build: Option<String>,
    }

    impl SemVer {
        /// Parse a version string into SemVer components
        pub fn parse(version: &str) -> Option<Self> {
            let version = version.trim().trim_start_matches('v');

            // Split off build metadata first
            let (version, build) = if let Some(idx) = version.find('+') {
                (&version[..idx], Some(version[idx + 1..].to_string()))
            } else {
                (version, None)
            };

            // Split off prerelease
            let (version, prerelease) = if let Some(idx) = version.find('-') {
                (&version[..idx], Some(version[idx + 1..].to_string()))
            } else {
                (version, None)
            };

            // Parse major.minor.patch
            let parts: Vec<&str> = version.split('.').collect();
            if parts.is_empty() || parts.len() > 3 {
                return None;
            }

            let major = parts.first()?.parse().ok()?;
            let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

            Some(Self {
                major,
                minor,
                patch,
                prerelease,
                build,
            })
        }

        /// Check if this version is a prerelease
        pub fn is_prerelease(&self) -> bool {
            self.prerelease.is_some()
        }
    }

    impl PartialOrd for SemVer {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for SemVer {
        fn cmp(&self, other: &Self) -> Ordering {
            // Compare major.minor.patch first
            match self.major.cmp(&other.major) {
                Ordering::Equal => {}
                ord => return ord,
            }
            match self.minor.cmp(&other.minor) {
                Ordering::Equal => {}
                ord => return ord,
            }
            match self.patch.cmp(&other.patch) {
                Ordering::Equal => {}
                ord => return ord,
            }

            // Prerelease versions are less than release versions
            match (&self.prerelease, &other.prerelease) {
                (None, None) => Ordering::Equal,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(a), Some(b)) => a.cmp(b),
            }
        }
    }

    /// Bump category for version changes
    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
    )]
    #[serde(rename_all = "lowercase")]
    pub enum BumpCategory {
        Patch,
        Minor,
        Major,
    }

    impl std::fmt::Display for BumpCategory {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                BumpCategory::Patch => write!(f, "patch"),
                BumpCategory::Minor => write!(f, "minor"),
                BumpCategory::Major => write!(f, "major"),
            }
        }
    }

    /// Classify the bump from one version to another
    pub fn classify_bump(from: &SemVer, to: &SemVer) -> BumpCategory {
        if from.major != to.major {
            BumpCategory::Major
        } else if from.minor != to.minor {
            BumpCategory::Minor
        } else {
            BumpCategory::Patch
        }
    }

    /// Compare two version strings
    pub fn compare_versions(a: &str, b: &str) -> Ordering {
        match (SemVer::parse(a), SemVer::parse(b)) {
            (Some(va), Some(vb)) => va.cmp(&vb),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => a.cmp(b), // Lexical fallback
        }
    }

    /// Check if version `check` is greater than `base`
    pub fn is_greater(check: &str, base: &str) -> bool {
        compare_versions(check, base) == Ordering::Greater
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_semver_parse() {
            let v = SemVer::parse("1.2.3").unwrap();
            assert_eq!(v.major, 1);
            assert_eq!(v.minor, 2);
            assert_eq!(v.patch, 3);
            assert!(v.prerelease.is_none());

            let v = SemVer::parse("2.0.0-alpha.1").unwrap();
            assert_eq!(v.major, 2);
            assert_eq!(v.prerelease, Some("alpha.1".to_string()));

            let v = SemVer::parse("v3.1.4").unwrap();
            assert_eq!(v.major, 3);
        }

        #[test]
        fn test_semver_ordering() {
            assert!(SemVer::parse("1.0.0").unwrap() < SemVer::parse("2.0.0").unwrap());
            assert!(SemVer::parse("1.0.0").unwrap() < SemVer::parse("1.1.0").unwrap());
            assert!(SemVer::parse("1.0.0").unwrap() < SemVer::parse("1.0.1").unwrap());
            assert!(SemVer::parse("1.0.0-alpha").unwrap() < SemVer::parse("1.0.0").unwrap());
        }

        #[test]
        fn test_classify_bump() {
            let from = SemVer::parse("1.2.3").unwrap();
            assert_eq!(
                classify_bump(&from, &SemVer::parse("1.2.4").unwrap()),
                BumpCategory::Patch
            );
            assert_eq!(
                classify_bump(&from, &SemVer::parse("1.3.0").unwrap()),
                BumpCategory::Minor
            );
            assert_eq!(
                classify_bump(&from, &SemVer::parse("2.0.0").unwrap()),
                BumpCategory::Major
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_prerelease_version() {
        assert!(VersionInfo::is_prerelease_version("1.0.0-alpha"));
        assert!(VersionInfo::is_prerelease_version("2.0.0-beta.1"));
        assert!(VersionInfo::is_prerelease_version("3.0.0-rc1"));
        assert!(!VersionInfo::is_prerelease_version("1.0.0"));
        assert!(!VersionInfo::is_prerelease_version("2.3.4"));
    }
}
