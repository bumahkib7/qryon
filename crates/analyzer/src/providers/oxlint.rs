//! Oxlint provider for JS/TS linting
//!
//! Integrates with [oxlint](https://oxc-project.github.io/docs/guide/usage/linter.html),
//! a high-performance Rust-native JavaScript/TypeScript linter with 500+ rules.
//!
//! This provider shells out to the oxlint CLI and parses its JSON output,
//! converting findings to RMA's unified Finding format.

use super::AnalysisProvider;
use anyhow::{Context, Result};
use rma_common::{
    Confidence, Finding, FindingCategory, FindingSource, Language, Severity, SourceLocation,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

/// Provider for oxlint integration
pub struct OxlintProvider {
    /// Path to oxlint binary (defaults to "oxlint" in PATH)
    binary_path: String,
    /// Whether oxlint is available on the system
    available: bool,
}

impl Default for OxlintProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OxlintProvider {
    /// Create a new OxlintProvider, checking if oxlint is available
    pub fn new() -> Self {
        let binary_path = "oxlint".to_string();
        let available = Self::check_availability(&binary_path);

        if available {
            info!("oxlint provider initialized successfully");
        } else {
            debug!("oxlint not found - JS/TS will use native rules only");
        }

        Self {
            binary_path,
            available,
        }
    }

    /// Create with a custom binary path
    pub fn with_binary(path: impl Into<String>) -> Self {
        let binary_path = path.into();
        let available = Self::check_availability(&binary_path);

        Self {
            binary_path,
            available,
        }
    }

    /// Check if oxlint is available
    fn check_availability(binary: &str) -> bool {
        Command::new(binary)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Returns true if oxlint is available on the system
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Get oxlint version if available
    pub fn version(&self) -> Option<String> {
        if !self.available {
            return None;
        }

        Command::new(&self.binary_path)
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    }

    /// Run oxlint on a directory and return findings
    pub fn lint_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        if !self.available {
            warn!("oxlint not available, returning empty results");
            return Ok(Vec::new());
        }

        let output = Command::new(&self.binary_path)
            .arg("--format")
            .arg("json")
            .arg(path)
            .output()
            .context("Failed to execute oxlint")?;

        // oxlint returns non-zero if it finds issues, so we check stderr for actual errors
        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Only warn if it's not just "found N problems"
            if !stderr.contains("problem") && !stderr.contains("warning") {
                debug!("oxlint stderr: {}", stderr);
            }
        }

        let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in oxlint output")?;

        if stdout.trim().is_empty() {
            return Ok(Vec::new());
        }

        self.parse_output(&stdout)
    }

    /// Run oxlint on a single file
    pub fn lint_file(&self, path: &Path) -> Result<Vec<Finding>> {
        if !self.available {
            return Ok(Vec::new());
        }

        let output = Command::new(&self.binary_path)
            .arg("--format")
            .arg("json")
            .arg(path)
            .output()
            .context("Failed to execute oxlint")?;

        let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in oxlint output")?;

        if stdout.trim().is_empty() {
            return Ok(Vec::new());
        }

        self.parse_output(&stdout)
    }

    /// Parse oxlint JSON output into RMA findings
    fn parse_output(&self, json_str: &str) -> Result<Vec<Finding>> {
        // oxlint outputs newline-delimited JSON (one object per line)
        // or an array depending on version
        let mut findings = Vec::new();

        // Try parsing as array first
        if let Ok(diagnostics) = serde_json::from_str::<Vec<OxlintDiagnostic>>(json_str) {
            for diag in diagnostics {
                if let Some(finding) = self.convert_diagnostic(diag) {
                    findings.push(finding);
                }
            }
            return Ok(findings);
        }

        // Fall back to newline-delimited JSON
        for line in json_str.lines() {
            let line = line.trim();
            if line.is_empty() || line == "[" || line == "]" {
                continue;
            }

            // Remove trailing comma if present
            let line = line.trim_end_matches(',');

            if let Ok(diag) = serde_json::from_str::<OxlintDiagnostic>(line)
                && let Some(finding) = self.convert_diagnostic(diag)
            {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

impl AnalysisProvider for OxlintProvider {
    fn name(&self) -> &'static str {
        "oxlint"
    }

    fn description(&self) -> &'static str {
        "High-performance Rust-native JavaScript/TypeScript linter"
    }

    fn supports_language(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn version(&self) -> Option<String> {
        OxlintProvider::version(self)
    }

    fn analyze_file(&self, path: &Path) -> Result<Vec<Finding>> {
        self.lint_file(path)
    }

    fn analyze_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        self.lint_directory(path)
    }
}

impl OxlintProvider {
    /// Convert an oxlint diagnostic to an RMA finding
    fn convert_diagnostic(&self, diag: OxlintDiagnostic) -> Option<Finding> {
        let severity = match diag.severity.as_deref() {
            Some("error") => Severity::Error,
            Some("warning") | Some("warn") => Severity::Warning,
            _ => Severity::Info,
        };

        // Map oxlint rule categories to confidence and category
        let (confidence, category) = if diag.rule_id.starts_with("security/")
            || diag.rule_id.contains("injection")
            || diag.rule_id.contains("xss")
        {
            (Confidence::High, FindingCategory::Security)
        } else if diag.rule_id.starts_with("correctness/")
            || diag.rule_id.starts_with("suspicious/")
        {
            (Confidence::Medium, FindingCategory::Quality)
        } else if diag.rule_id.starts_with("perf/") || diag.rule_id.starts_with("performance/") {
            (Confidence::Medium, FindingCategory::Performance)
        } else {
            (Confidence::Low, FindingCategory::Style)
        };

        let line = diag.start_line.unwrap_or(1);
        let column = diag.start_column.unwrap_or(1);
        let rule_id = format!("oxlint/{}", diag.rule_id);

        let location = SourceLocation::new(
            PathBuf::from(&diag.filename),
            line,
            column,
            line,   // end_line same as start for single point
            column, // end_column same as start
        );

        Some(Finding {
            id: format!("{}:{}:{}", rule_id, diag.filename, line),
            rule_id,
            message: diag.message,
            severity,
            location,
            language: Language::JavaScript, // oxlint handles JS/TS
            snippet: diag.source,
            suggestion: None,
            fix: None,
            confidence,
            category,
            source: FindingSource::Oxlint,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        })
    }
}

/// Oxlint diagnostic structure (from JSON output)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OxlintDiagnostic {
    /// The rule that triggered this diagnostic
    #[serde(alias = "ruleId", alias = "rule")]
    rule_id: String,

    /// The diagnostic message
    message: String,

    /// Source file path
    #[serde(alias = "file", alias = "filePath")]
    filename: String,

    /// Severity level
    severity: Option<String>,

    /// Starting line (1-indexed)
    #[serde(alias = "line")]
    start_line: Option<usize>,

    /// Starting column (1-indexed)
    #[serde(alias = "column")]
    start_column: Option<usize>,

    /// Source code snippet
    source: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = OxlintProvider::new();
        // Just test that it doesn't panic - availability depends on system
        let _ = provider.is_available();
    }

    #[test]
    fn test_parse_json_array() {
        let provider = OxlintProvider::new();

        let json = r#"[
            {
                "ruleId": "no-unused-vars",
                "message": "Variable 'x' is declared but never used",
                "filename": "test.js",
                "severity": "warning",
                "line": 5,
                "column": 10
            }
        ]"#;

        let findings = provider.parse_output(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "oxlint/no-unused-vars");
        assert_eq!(findings[0].location.start_line, 5);
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_parse_ndjson() {
        let provider = OxlintProvider::new();

        let json = r#"{"ruleId": "security/detect-eval", "message": "eval is dangerous", "filename": "app.js", "severity": "error", "line": 10, "column": 1}
{"ruleId": "no-console", "message": "Unexpected console statement", "filename": "app.js", "severity": "warning", "line": 15, "column": 5}"#;

        let findings = provider.parse_output(json).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "oxlint/security/detect-eval");
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].confidence, Confidence::High); // security/ prefix
    }

    #[test]
    fn test_severity_mapping() {
        let provider = OxlintProvider::new();

        let json = r#"[
            {"ruleId": "test1", "message": "m", "filename": "f", "severity": "error", "line": 1},
            {"ruleId": "test2", "message": "m", "filename": "f", "severity": "warning", "line": 1},
            {"ruleId": "test3", "message": "m", "filename": "f", "severity": "info", "line": 1}
        ]"#;

        let findings = provider.parse_output(json).unwrap();
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[1].severity, Severity::Warning);
        assert_eq!(findings[2].severity, Severity::Info);
    }

    #[test]
    fn test_confidence_and_category_mapping() {
        let provider = OxlintProvider::new();

        let json = r#"[
            {"ruleId": "security/detect-xss", "message": "m", "filename": "f", "line": 1},
            {"ruleId": "correctness/no-unused-vars", "message": "m", "filename": "f", "line": 1},
            {"ruleId": "perf/no-barrel-file", "message": "m", "filename": "f", "line": 1},
            {"ruleId": "style/no-tabs", "message": "m", "filename": "f", "line": 1}
        ]"#;

        let findings = provider.parse_output(json).unwrap();
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[0].category, FindingCategory::Security);

        assert_eq!(findings[1].confidence, Confidence::Medium);
        assert_eq!(findings[1].category, FindingCategory::Quality);

        assert_eq!(findings[2].confidence, Confidence::Medium);
        assert_eq!(findings[2].category, FindingCategory::Performance);

        assert_eq!(findings[3].confidence, Confidence::Low);
        assert_eq!(findings[3].category, FindingCategory::Style);
    }
}
