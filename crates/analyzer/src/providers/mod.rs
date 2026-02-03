//! Linter providers for extended language support
//!
//! This module provides integration with linters for extended coverage.
//! Providers can be native Rust libraries or external CLI tools.
//!
//! # Provider Architecture
//!
//! Providers implement the `AnalysisProvider` trait which allows them to:
//! - Declare which languages they support
//! - Analyze files and return unified `Finding` results
//! - Report their availability status
//!
//! # Supported Providers
//!
//! ## Native Rust (preferred - no external dependencies)
//! - `oxc_native` - Native oxc_linter integration (520+ JS/TS rules)
//! - `rustsec` - RustSec Advisory Database for Rust dependencies
//! - `osv` - OSV.dev multi-language dependency vulnerability scanning
//!
//! ## External CLI (fallback - requires installation)
//! - `oxlint` - oxlint CLI for JS/TS (if native not suitable)
//! - `pmd` - PMD for Java security and quality analysis
//! - `gosec` - Go Security Checker for Go security analysis

pub mod gosec;
pub mod osv;
pub mod osv_db;
#[cfg(feature = "oxc")]
pub mod oxc_native;
pub mod oxlint;
pub mod pmd;
pub mod registry;
pub mod rustsec;

pub use gosec::GosecProvider;
pub use osv::OsvProvider;
pub use osv_db::{OsvDatabase, OsvVulnerability, VulnMatch};
#[cfg(feature = "oxc")]
pub use oxc_native::OxcNativeProvider;
pub use oxlint::OxlintProvider;
pub use pmd::PmdProvider;
pub use rustsec::RustSecProvider;

use anyhow::Result;
use rma_common::{Finding, Language};
use std::path::Path;

/// Trait for external analysis providers
///
/// Providers integrate external linters/analyzers into RMA's unified
/// finding pipeline. Each provider:
/// - Reports which languages it can analyze
/// - Runs its external tool and parses results
/// - Converts findings to RMA's `Finding` format
///
/// # Example
///
/// ```ignore
/// let pmd = PmdProvider::new(config);
/// if pmd.is_available() && pmd.supports_language(Language::Java) {
///     let findings = pmd.analyze_directory(path)?;
///     // findings are Vec<Finding> in unified format
/// }
/// ```
pub trait AnalysisProvider: Send + Sync {
    /// Unique identifier for this provider (e.g., "pmd", "oxlint")
    fn name(&self) -> &'static str;

    /// Human-readable description of the provider
    fn description(&self) -> &'static str;

    /// Check if this provider supports the given language
    fn supports_language(&self, lang: Language) -> bool;

    /// Check if the provider is available (tool is installed, configured)
    fn is_available(&self) -> bool;

    /// Get the version of the external tool (if available)
    fn version(&self) -> Option<String>;

    /// Analyze a single file and return findings
    ///
    /// This may shell out to an external tool or use internal analysis.
    fn analyze_file(&self, path: &Path) -> Result<Vec<Finding>>;

    /// Analyze a directory and return findings for all supported files
    ///
    /// Default implementation analyzes each file individually, but providers
    /// can override this for batch analysis (more efficient for external tools).
    fn analyze_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        // Default: delegate to file analysis
        // Providers should override for batch processing
        self.analyze_file(path)
    }

    /// Analyze multiple files and return findings
    ///
    /// Providers can override this for efficient batch analysis.
    fn analyze_files(&self, files: &[&Path]) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();
        for file in files {
            let findings = self.analyze_file(file)?;
            all_findings.extend(findings);
        }
        Ok(all_findings)
    }
}

/// Registry of available providers
pub struct ProviderRegistry {
    providers: Vec<Box<dyn AnalysisProvider>>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderRegistry {
    /// Create an empty provider registry
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Register a provider
    pub fn register(&mut self, provider: Box<dyn AnalysisProvider>) {
        self.providers.push(provider);
    }

    /// Get all registered providers
    pub fn providers(&self) -> &[Box<dyn AnalysisProvider>] {
        &self.providers
    }

    /// Get providers that support a specific language
    pub fn providers_for_language(&self, lang: Language) -> Vec<&dyn AnalysisProvider> {
        self.providers
            .iter()
            .filter(|p| p.is_available() && p.supports_language(lang))
            .map(|p| p.as_ref())
            .collect()
    }

    /// Get a provider by name
    pub fn get(&self, name: &str) -> Option<&dyn AnalysisProvider> {
        self.providers
            .iter()
            .find(|p| p.name() == name)
            .map(|p| p.as_ref())
    }

    /// Check if any provider supports the given language
    pub fn has_provider_for(&self, lang: Language) -> bool {
        self.providers
            .iter()
            .any(|p| p.is_available() && p.supports_language(lang))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider {
        name: &'static str,
        available: bool,
        languages: Vec<Language>,
    }

    impl AnalysisProvider for MockProvider {
        fn name(&self) -> &'static str {
            self.name
        }

        fn description(&self) -> &'static str {
            "Mock provider for testing"
        }

        fn supports_language(&self, lang: Language) -> bool {
            self.languages.contains(&lang)
        }

        fn is_available(&self) -> bool {
            self.available
        }

        fn version(&self) -> Option<String> {
            Some("1.0.0".to_string())
        }

        fn analyze_file(&self, _path: &Path) -> Result<Vec<Finding>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn test_registry_providers_for_language() {
        let mut registry = ProviderRegistry::new();

        registry.register(Box::new(MockProvider {
            name: "java-linter",
            available: true,
            languages: vec![Language::Java],
        }));

        registry.register(Box::new(MockProvider {
            name: "js-linter",
            available: true,
            languages: vec![Language::JavaScript, Language::TypeScript],
        }));

        let java_providers = registry.providers_for_language(Language::Java);
        assert_eq!(java_providers.len(), 1);
        assert_eq!(java_providers[0].name(), "java-linter");

        let js_providers = registry.providers_for_language(Language::JavaScript);
        assert_eq!(js_providers.len(), 1);
        assert_eq!(js_providers[0].name(), "js-linter");
    }

    #[test]
    fn test_registry_unavailable_provider() {
        let mut registry = ProviderRegistry::new();

        registry.register(Box::new(MockProvider {
            name: "unavailable",
            available: false,
            languages: vec![Language::Java],
        }));

        let providers = registry.providers_for_language(Language::Java);
        assert!(providers.is_empty());
    }
}
