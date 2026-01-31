//! Code analysis and security scanning for Rust Monorepo Analyzer
//!
//! This crate provides metrics computation, vulnerability detection,
//! and pattern-based analysis on parsed ASTs.
//!
//! NOTE: This crate DETECTS security vulnerabilities - it does not contain them.
//! The security rules detect dangerous patterns like unsafe code, code injection, etc.

pub mod metrics;
pub mod rules;
pub mod security;

use anyhow::Result;
use rayon::prelude::*;
use rma_common::{CodeMetrics, Finding, Language, RmaConfig, Severity};
use rma_parser::ParsedFile;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, instrument};

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
pub struct AnalyzerEngine {
    config: Arc<RmaConfig>,
    rules: Vec<Box<dyn rules::Rule + Send + Sync>>,
}

impl AnalyzerEngine {
    /// Create a new analyzer with default rules
    pub fn new(config: RmaConfig) -> Self {
        let mut engine = Self {
            config: Arc::new(config),
            rules: Vec::new(),
        };
        engine.register_default_rules();
        engine
    }

    /// Register all default security and quality rules
    fn register_default_rules(&mut self) {
        // Rust rules - DETECT dangerous patterns
        self.rules.push(Box::new(security::rust::UnsafeBlockRule));
        self.rules.push(Box::new(security::rust::UnwrapRule));
        self.rules.push(Box::new(security::rust::PanicRule));
        self.rules.push(Box::new(security::rust::TransmuteRule));
        self.rules.push(Box::new(security::rust::RawPointerDerefRule));
        self.rules.push(Box::new(security::rust::CommandInjectionRule));
        self.rules.push(Box::new(security::rust::SqlInjectionRule));
        self.rules.push(Box::new(security::rust::UncheckedIndexRule));
        self.rules.push(Box::new(security::rust::PathTraversalRule));

        // JavaScript rules - DETECT dangerous patterns
        self.rules
            .push(Box::new(security::javascript::DynamicCodeExecutionRule));
        self.rules
            .push(Box::new(security::javascript::TimerStringRule));
        self.rules
            .push(Box::new(security::javascript::InnerHtmlRule));
        self.rules
            .push(Box::new(security::javascript::ConsoleLogRule));

        // Python rules - DETECT dangerous patterns
        self.rules
            .push(Box::new(security::python::DynamicExecutionRule));
        self.rules
            .push(Box::new(security::python::ShellInjectionRule));
        self.rules
            .push(Box::new(security::python::HardcodedSecretRule));

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
    }

    /// Analyze a single parsed file
    #[instrument(skip(self, parsed), fields(path = %parsed.path.display()))]
    pub fn analyze_file(&self, parsed: &ParsedFile) -> Result<FileAnalysis> {
        let metrics = metrics::compute_metrics(parsed);

        let mut findings = Vec::new();

        // Run all applicable rules
        for rule in &self.rules {
            if rule.applies_to(parsed.language) {
                let rule_findings = rule.check(parsed);
                findings.extend(rule_findings);
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
        assert!(analysis
            .findings
            .iter()
            .any(|f| f.rule_id.contains("unsafe")));
    }
}
