//! Code analysis and security scanning for Rust Monorepo Analyzer
//!
//! This crate provides metrics computation, vulnerability detection,
//! and pattern-based analysis on parsed ASTs.
//!
//! NOTE: This crate DETECTS security vulnerabilities - it does not contain them.
//! The security rules detect dangerous patterns like unsafe code, code injection, etc.

pub mod metrics;
pub mod providers;
pub mod rules;
pub mod security;

use anyhow::Result;
use providers::{AnalysisProvider, PmdProvider, ProviderRegistry};
use rayon::prelude::*;
use rma_common::{
    CodeMetrics, Finding, Language, ProviderType, ProvidersConfig, RmaConfig, Severity,
};
use rma_parser::ParsedFile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

/// Results from analyzing a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysis {
    pub path: String,
    pub language: Language,
    pub metrics: CodeMetrics,
    pub findings: Vec<Finding>,
}

/// Summary of analysis results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub files_analyzed: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub total_complexity: usize,
    pub total_loc: usize,
}

/// The main analysis engine
///
/// Combines native RMA rules with optional external providers (PMD, Oxlint)
/// for comprehensive code analysis across multiple languages.
pub struct AnalyzerEngine {
    config: Arc<RmaConfig>,
    rules: Vec<Box<dyn rules::Rule + Send + Sync>>,
    /// Pre-filtered rule indices by language for O(1) lookup
    rules_by_language: HashMap<Language, Vec<usize>>,
    provider_registry: ProviderRegistry,
    enabled_providers: Vec<ProviderType>,
}

impl AnalyzerEngine {
    /// Create a new analyzer with default rules (no external providers)
    pub fn new(config: RmaConfig) -> Self {
        Self::with_providers(config, ProvidersConfig::default())
    }

    /// Create a new analyzer with specified providers
    pub fn with_providers(config: RmaConfig, providers_config: ProvidersConfig) -> Self {
        let mut engine = Self {
            config: Arc::new(config),
            rules: Vec::new(),
            rules_by_language: HashMap::new(),
            provider_registry: ProviderRegistry::new(),
            enabled_providers: providers_config.enabled.clone(),
        };
        engine.register_default_rules();
        engine.build_language_index();
        engine.register_providers(&providers_config);
        engine
    }

    /// Build index of rules by language for O(1) lookup
    fn build_language_index(&mut self) {
        let languages = [
            Language::Rust,
            Language::JavaScript,
            Language::TypeScript,
            Language::Python,
            Language::Go,
            Language::Java,
            Language::Unknown,
        ];

        for lang in languages {
            let indices: Vec<usize> = self
                .rules
                .iter()
                .enumerate()
                .filter(|(_, rule)| rule.applies_to(lang))
                .map(|(i, _)| i)
                .collect();
            self.rules_by_language.insert(lang, indices);
        }
    }

    /// Register external providers based on configuration
    fn register_providers(&mut self, config: &ProvidersConfig) {
        for provider_type in &config.enabled {
            match provider_type {
                ProviderType::Rma => {
                    // RMA is always enabled via native rules, nothing to register
                    debug!("RMA native rules enabled");
                }
                ProviderType::Pmd => {
                    let pmd = PmdProvider::new(config.pmd.clone());
                    if pmd.is_available() {
                        info!("PMD provider registered (version: {:?})", pmd.version());
                        self.provider_registry.register(Box::new(pmd));
                    } else {
                        warn!(
                            "PMD provider enabled but not available - check pmd_path configuration"
                        );
                    }
                }
                ProviderType::Oxlint => {
                    let oxlint = providers::OxlintProvider::new();
                    if oxlint.is_available() {
                        info!(
                            "Oxlint provider registered (version: {:?})",
                            oxlint.version()
                        );
                        self.provider_registry.register(Box::new(oxlint));
                    } else {
                        warn!(
                            "Oxlint provider enabled but not available - install oxlint or check binary_path"
                        );
                    }
                }
                ProviderType::RustSec => {
                    let rustsec = providers::RustSecProvider::new();
                    if rustsec.is_available() {
                        info!(
                            "RustSec provider registered (version: {:?})",
                            rustsec.version()
                        );
                        self.provider_registry.register(Box::new(rustsec));
                    } else {
                        warn!(
                            "RustSec provider enabled but database unavailable - check network connection"
                        );
                    }
                }
                ProviderType::Gosec => {
                    let gosec = providers::GosecProvider::new(config.gosec.clone());
                    if gosec.is_available() {
                        info!("Gosec provider registered (version: {:?})", gosec.version());
                        self.provider_registry.register(Box::new(gosec));
                    } else {
                        warn!(
                            "Gosec provider enabled but not available - install gosec: go install github.com/securego/gosec/v2/cmd/gosec@latest"
                        );
                    }
                }
                #[cfg(feature = "oxc")]
                ProviderType::Oxc => {
                    let oxc = providers::OxcNativeProvider::new();
                    if oxc.is_available() {
                        info!(
                            "Oxc native provider registered (version: {:?})",
                            oxc.version()
                        );
                        self.provider_registry.register(Box::new(oxc));
                    }
                }
                #[cfg(not(feature = "oxc"))]
                ProviderType::Oxc => {
                    warn!("Oxc provider not available - compiled without oxc feature");
                }
                ProviderType::Osv => {
                    let osv = providers::OsvProvider::new(config.osv.clone());
                    if osv.is_available() {
                        info!("OSV provider registered (version: {:?})", osv.version());
                        self.provider_registry.register(Box::new(osv));
                    } else {
                        // This should never happen since OsvProvider is always available
                        warn!("OSV provider unexpectedly unavailable");
                    }
                }
            }
        }
    }

    /// Check if a provider is enabled
    pub fn is_provider_enabled(&self, provider_type: ProviderType) -> bool {
        self.enabled_providers.contains(&provider_type)
    }

    /// Get list of available providers
    pub fn available_providers(&self) -> Vec<&str> {
        self.provider_registry
            .providers()
            .iter()
            .map(|p| p.name())
            .collect()
    }

    /// Register all default security and quality rules
    fn register_default_rules(&mut self) {
        // =====================================================================
        // RUST RULES
        // =====================================================================

        // Section A: High-confidence sinks (precise detection)
        self.rules.push(Box::new(security::rust::UnsafeBlockRule));
        self.rules.push(Box::new(security::rust::TransmuteRule));
        self.rules
            .push(Box::new(security::rust::CommandInjectionRule));
        self.rules.push(Box::new(security::rust::ShellSpawnRule));
        self.rules
            .push(Box::new(security::rust::RawPointerDerefRule));

        // Section B: Review hints (low confidence, need verification)
        self.rules.push(Box::new(security::rust::SqlInjectionHint));
        self.rules.push(Box::new(security::rust::PathTraversalHint));
        self.rules.push(Box::new(security::rust::UnwrapHint));
        self.rules.push(Box::new(security::rust::PanicHint));

        // JavaScript rules - DETECT dangerous patterns
        // Security sinks
        self.rules
            .push(Box::new(security::javascript::DynamicCodeExecutionRule));
        self.rules
            .push(Box::new(security::javascript::TimerStringRule));
        self.rules
            .push(Box::new(security::javascript::InnerHtmlRule));
        self.rules
            .push(Box::new(security::javascript::InnerHtmlReadRule));
        self.rules
            .push(Box::new(security::javascript::JsxScriptUrlRule));
        self.rules
            .push(Box::new(security::javascript::DangerousHtmlRule));
        self.rules
            .push(Box::new(security::javascript::NoDocumentWriteRule));
        // Code quality
        self.rules
            .push(Box::new(security::javascript::ConsoleLogRule));
        self.rules
            .push(Box::new(security::javascript::DebuggerStatementRule));
        self.rules.push(Box::new(security::javascript::NoAlertRule));
        // Correctness
        self.rules
            .push(Box::new(security::javascript::StrictEqualityRule));
        self.rules
            .push(Box::new(security::javascript::NoConditionAssignRule));
        self.rules
            .push(Box::new(security::javascript::NoConstantConditionRule));
        self.rules
            .push(Box::new(security::javascript::ValidTypeofRule));
        self.rules.push(Box::new(security::javascript::NoWithRule));

        // Python rules - DETECT dangerous patterns
        self.rules
            .push(Box::new(security::python::DynamicExecutionRule));
        self.rules
            .push(Box::new(security::python::ShellInjectionRule));
        self.rules
            .push(Box::new(security::python::HardcodedSecretRule));

        // =====================================================================
        // GO RULES
        // =====================================================================

        // Section A: High-confidence sinks
        self.rules
            .push(Box::new(security::go::CommandInjectionRule));
        self.rules.push(Box::new(security::go::SqlInjectionRule));
        self.rules.push(Box::new(security::go::UnsafePointerRule));
        self.rules.push(Box::new(security::go::InsecureHttpRule));

        // Section B: Review hints
        self.rules.push(Box::new(security::go::IgnoredErrorHint));

        // =====================================================================
        // JAVA RULES
        // =====================================================================

        // Section A: High-confidence sinks
        self.rules
            .push(Box::new(security::java::CommandExecutionRule));
        self.rules.push(Box::new(security::java::SqlInjectionRule));
        self.rules
            .push(Box::new(security::java::InsecureDeserializationRule));
        self.rules
            .push(Box::new(security::java::XxeVulnerabilityRule));
        self.rules.push(Box::new(security::java::PathTraversalRule));

        // Section B: Review hints
        self.rules
            .push(Box::new(security::java::GenericExceptionHint));
        self.rules.push(Box::new(security::java::SystemOutHint));

        // =====================================================================
        // GENERIC RULES (apply to all languages)
        // =====================================================================

        // Generic rules (apply to all languages)
        self.rules.push(Box::new(security::generic::TodoFixmeRule));
        self.rules
            .push(Box::new(security::generic::LongFunctionRule::new(100)));
        self.rules
            .push(Box::new(security::generic::HighComplexityRule::new(15)));
        self.rules
            .push(Box::new(security::generic::HardcodedSecretRule));
        self.rules
            .push(Box::new(security::generic::InsecureCryptoRule));
        self.rules
            .push(Box::new(security::generic::DuplicateFunctionRule::new(10))); // Min 10 lines
    }

    /// Analyze a single parsed file using native rules only
    #[instrument(skip(self, parsed), fields(path = %parsed.path.display()))]
    pub fn analyze_file(&self, parsed: &ParsedFile) -> Result<FileAnalysis> {
        let metrics = metrics::compute_metrics(parsed);

        let mut findings = Vec::new();

        // Run only applicable rules using pre-built language index (O(1) lookup)
        if let Some(rule_indices) = self.rules_by_language.get(&parsed.language) {
            for &idx in rule_indices {
                let rule_findings = self.rules[idx].check(parsed);
                findings.extend(rule_findings);
            }
        }

        // Run applicable providers on this file
        for provider in self.provider_registry.providers() {
            if provider.supports_language(parsed.language) {
                match provider.analyze_file(&parsed.path) {
                    Ok(provider_findings) => {
                        debug!(
                            "Provider {} found {} findings for {}",
                            provider.name(),
                            provider_findings.len(),
                            parsed.path.display()
                        );
                        findings.extend(provider_findings);
                    }
                    Err(e) => {
                        warn!(
                            "Provider {} failed for {}: {}",
                            provider.name(),
                            parsed.path.display(),
                            e
                        );
                    }
                }
            }
        }

        // Filter by minimum severity
        findings.retain(|f| f.severity >= self.config.min_severity);

        debug!(
            "Analyzed {} - {} findings, complexity {}",
            parsed.path.display(),
            findings.len(),
            metrics.cyclomatic_complexity
        );

        Ok(FileAnalysis {
            path: parsed.path.to_string_lossy().to_string(),
            language: parsed.language,
            metrics,
            findings,
        })
    }

    /// Analyze multiple parsed files in parallel
    #[instrument(skip(self, files))]
    pub fn analyze_files(
        &self,
        files: &[ParsedFile],
    ) -> Result<(Vec<FileAnalysis>, AnalysisSummary)> {
        info!("Starting parallel analysis of {} files", files.len());

        let results: Vec<FileAnalysis> = files
            .par_iter()
            .filter_map(|parsed| self.analyze_file(parsed).ok())
            .collect();

        let summary = compute_summary(&results);

        info!(
            "Analysis complete: {} files, {} findings ({} critical)",
            summary.files_analyzed, summary.total_findings, summary.critical_count
        );

        Ok((results, summary))
    }

    /// Run provider analysis on a directory
    ///
    /// This is more efficient for providers that support batch analysis
    /// (like PMD which can analyze a whole directory at once).
    #[instrument(skip(self))]
    pub fn analyze_directory_with_providers(&self, path: &Path) -> Result<Vec<Finding>> {
        let mut all_findings = Vec::new();

        for provider in self.provider_registry.providers() {
            if provider.is_available() {
                info!("Running {} on {}", provider.name(), path.display());
                match provider.analyze_directory(path) {
                    Ok(findings) => {
                        info!("{} found {} findings", provider.name(), findings.len());
                        all_findings.extend(findings);
                    }
                    Err(e) => {
                        warn!("Provider {} failed: {}", provider.name(), e);
                    }
                }
            }
        }

        // Filter by minimum severity
        all_findings.retain(|f| f.severity >= self.config.min_severity);

        Ok(all_findings)
    }

    /// Analyze files with both native rules and providers
    ///
    /// This combines:
    /// 1. Native rule analysis (per-file, parallel)
    /// 2. Provider analysis (batch where possible)
    #[instrument(skip(self, files))]
    pub fn analyze_files_with_providers(
        &self,
        files: &[ParsedFile],
        base_path: &Path,
    ) -> Result<(Vec<FileAnalysis>, AnalysisSummary)> {
        info!(
            "Starting analysis of {} files with {} providers",
            files.len(),
            self.provider_registry.providers().len()
        );

        // Step 1: Run native rules in parallel using pre-indexed rules
        let results: Vec<FileAnalysis> = files
            .par_iter()
            .filter_map(|parsed| {
                let metrics = metrics::compute_metrics(parsed);
                let mut findings = Vec::new();

                // Run only applicable rules using pre-built language index
                if let Some(rule_indices) = self.rules_by_language.get(&parsed.language) {
                    for &idx in rule_indices {
                        findings.extend(self.rules[idx].check(parsed));
                    }
                }

                Some(FileAnalysis {
                    path: parsed.path.display().to_string(),
                    language: parsed.language,
                    metrics,
                    findings,
                })
            })
            .collect();

        // Step 2: Build HashMap for O(1) result lookups
        let mut results_map: HashMap<String, FileAnalysis> =
            results.into_iter().map(|r| (r.path.clone(), r)).collect();

        // Step 3: Run providers on the directory (more efficient for tools like PMD)
        let provider_findings = self.analyze_directory_with_providers(base_path)?;

        // Step 4: Merge provider findings into file results using O(1) HashMap lookup
        for finding in provider_findings {
            let file_path = finding.location.file.display().to_string();
            if let Some(result) = results_map.get_mut(&file_path) {
                result.findings.push(finding);
            } else {
                // File wasn't in parsed files - create a new result
                results_map.insert(
                    file_path.clone(),
                    FileAnalysis {
                        path: file_path,
                        language: finding.language,
                        metrics: CodeMetrics::default(),
                        findings: vec![finding],
                    },
                );
            }
        }

        // Convert back to Vec
        let mut results: Vec<FileAnalysis> = results_map.into_values().collect();

        // Step 4: Filter by severity
        for result in &mut results {
            result
                .findings
                .retain(|f| f.severity >= self.config.min_severity);
        }

        let summary = compute_summary(&results);

        info!(
            "Analysis complete: {} files, {} findings ({} critical)",
            summary.files_analyzed, summary.total_findings, summary.critical_count
        );

        Ok((results, summary))
    }
}

/// Compute aggregate summary from analysis results
fn compute_summary(results: &[FileAnalysis]) -> AnalysisSummary {
    let mut summary = AnalysisSummary {
        files_analyzed: results.len(),
        ..Default::default()
    };

    for result in results {
        summary.total_loc += result.metrics.lines_of_code;
        summary.total_complexity += result.metrics.cyclomatic_complexity;

        for finding in &result.findings {
            summary.total_findings += 1;
            match finding.severity {
                Severity::Critical => summary.critical_count += 1,
                Severity::Error => summary.error_count += 1,
                Severity::Warning => summary.warning_count += 1,
                Severity::Info => summary.info_count += 1,
            }
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_parser::ParserEngine;
    use std::path::Path;

    #[test]
    fn test_analyze_rust_file_with_unsafe() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config.clone());
        let analyzer = AnalyzerEngine::new(config);

        let content = r#"
fn safe_function() {
    println!("Safe!");
}

fn risky_function() {
    unsafe {
        std::ptr::null::<i32>();
    }
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let analysis = analyzer.analyze_file(&parsed).unwrap();

        // Should detect the unsafe block
        assert!(
            analysis
                .findings
                .iter()
                .any(|f| f.rule_id.contains("unsafe"))
        );
    }
}
