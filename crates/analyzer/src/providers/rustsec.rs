//! RustSec provider for Rust dependency vulnerability scanning
//!
//! Integrates with the [RustSec Advisory Database](https://rustsec.org/) to detect
//! known vulnerabilities in Cargo.lock dependencies.

use super::AnalysisProvider;
use anyhow::{Context, Result};
use rma_common::{Confidence, Finding, FindingCategory, Language, Severity, SourceLocation};
use rustsec::{Database, Lockfile, Vulnerability};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Provider for RustSec vulnerability scanning
pub struct RustSecProvider {
    database: Option<Database>,
    available: bool,
}

impl Default for RustSecProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl RustSecProvider {
    /// Create a new RustSecProvider, fetching the advisory database
    pub fn new() -> Self {
        match Database::fetch() {
            Ok(db) => {
                info!("RustSec database loaded ({} advisories)", db.iter().count());
                Self {
                    database: Some(db),
                    available: true,
                }
            }
            Err(e) => {
                warn!("Failed to fetch RustSec database: {}", e);
                Self {
                    database: None,
                    available: false,
                }
            }
        }
    }

    /// Create with an existing database (for testing)
    pub fn with_database(db: Database) -> Self {
        Self {
            database: Some(db),
            available: true,
        }
    }

    /// Scan a Cargo.lock file for vulnerabilities
    pub fn scan_lockfile(&self, lockfile_path: &Path) -> Result<Vec<Finding>> {
        let db = self
            .database
            .as_ref()
            .context("RustSec database not available")?;

        let lockfile = Lockfile::load(lockfile_path)
            .with_context(|| format!("Failed to load lockfile: {}", lockfile_path.display()))?;

        let vulnerabilities = db.vulnerabilities(&lockfile);

        debug!(
            "Found {} vulnerabilities in {}",
            vulnerabilities.len(),
            lockfile_path.display()
        );

        let findings: Vec<Finding> = vulnerabilities
            .iter()
            .map(|vuln| self.vuln_to_finding(vuln, lockfile_path))
            .collect();

        Ok(findings)
    }

    /// Convert a RustSec vulnerability to an RMA Finding
    fn vuln_to_finding(&self, vuln: &Vulnerability, lockfile_path: &Path) -> Finding {
        let advisory = &vuln.advisory;

        // Map CVSS score to severity
        let severity = if let Some(cvss) = &advisory.cvss {
            let score = cvss.score();
            match score {
                s if s >= 9.0 => Severity::Critical,
                s if s >= 7.0 => Severity::Error,
                s if s >= 4.0 => Severity::Warning,
                _ => Severity::Info,
            }
        } else {
            // Default to Warning if no CVSS score
            Severity::Warning
        };

        let rule_id = format!("rustsec/{}", advisory.id);
        let package_name = &vuln.package.name;
        let package_version = &vuln.package.version;

        let message = format!(
            "{} v{}: {} ({})",
            package_name, package_version, advisory.title, advisory.id
        );

        // Build suggestion with patched versions
        let mut suggestion = format!("Advisory: {}", advisory.id);

        // Extract patched versions from the vulnerability (not advisory)
        let patched = vuln.versions.patched();
        if !patched.is_empty() {
            let patched_strs: Vec<String> = patched.iter().map(|v| v.to_string()).collect();
            suggestion.push_str(&format!("\nPatched in: {}", patched_strs.join(", ")));
        }

        // Extract unaffected versions
        let unaffected = vuln.versions.unaffected();
        if !unaffected.is_empty() {
            let unaffected_strs: Vec<String> = unaffected.iter().map(|v| v.to_string()).collect();
            suggestion.push_str(&format!("\nUnaffected: {}", unaffected_strs.join(", ")));
        }

        if let Some(url) = &advisory.url {
            suggestion.push_str(&format!("\nMore info: {}", url));
        }

        Finding {
            id: format!("{}:{}:{}", rule_id, package_name, package_version),
            rule_id,
            message,
            severity,
            location: SourceLocation::new(lockfile_path.to_path_buf(), 1, 1, 1, 1),
            language: Language::Rust,
            snippet: Some(format!("{} = \"{}\"", package_name, package_version)),
            suggestion: Some(suggestion),
            fix: None,
            confidence: Confidence::High,
            category: FindingCategory::Security,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        }
    }

    /// Find all Cargo.lock files in a directory
    fn find_lockfiles(&self, path: &Path) -> Vec<PathBuf> {
        let mut lockfiles = Vec::new();

        // Check for Cargo.lock in the root
        let root_lock = path.join("Cargo.lock");
        if root_lock.exists() {
            lockfiles.push(root_lock);
        }

        // Also check in common locations for workspaces
        for entry in walkdir::WalkDir::new(path)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_name() == "Cargo.lock" {
                let lock_path = entry.path().to_path_buf();
                if !lockfiles.contains(&lock_path) {
                    lockfiles.push(lock_path);
                }
            }
        }

        lockfiles
    }
}

impl AnalysisProvider for RustSecProvider {
    fn name(&self) -> &'static str {
        "rustsec"
    }

    fn description(&self) -> &'static str {
        "RustSec Advisory Database - scans Cargo.lock for known vulnerabilities"
    }

    fn supports_language(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn version(&self) -> Option<String> {
        self.database
            .as_ref()
            .map(|db| format!("RustSec DB ({} advisories)", db.iter().count()))
    }

    fn analyze_file(&self, path: &Path) -> Result<Vec<Finding>> {
        // Only process Cargo.lock files
        if path.file_name().map(|n| n == "Cargo.lock").unwrap_or(false) {
            self.scan_lockfile(path)
        } else {
            Ok(Vec::new())
        }
    }

    fn analyze_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        if !self.available {
            return Ok(Vec::new());
        }

        let lockfiles = self.find_lockfiles(path);
        let mut all_findings = Vec::new();

        for lockfile in lockfiles {
            match self.scan_lockfile(&lockfile) {
                Ok(findings) => {
                    info!(
                        "RustSec: {} vulnerabilities in {}",
                        findings.len(),
                        lockfile.display()
                    );
                    all_findings.extend(findings);
                }
                Err(e) => {
                    warn!("Failed to scan {}: {}", lockfile.display(), e);
                }
            }
        }

        Ok(all_findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        // This test may fail if network is unavailable
        let provider = RustSecProvider::new();
        // Just verify it doesn't panic
        let _ = provider.is_available();
    }
}
