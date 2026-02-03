//! Gosec provider for Go security analysis
//!
//! Integrates with [gosec](https://github.com/securego/gosec), the Go Security Checker
//! which inspects source code for security problems by scanning the Go AST.
//!
//! This provider shells out to the gosec CLI and parses its JSON output,
//! converting findings to RMA's unified Finding format.

use super::AnalysisProvider;
use anyhow::{Context, Result};
use rma_common::{
    Confidence, Finding, FindingCategory, GosecProviderConfig, Language, Severity, SourceLocation,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

/// Provider for gosec integration
pub struct GosecProvider {
    /// Path to gosec binary (defaults to "gosec" in PATH)
    binary_path: String,
    /// Whether gosec is available on the system
    available: bool,
    /// Configuration
    config: GosecProviderConfig,
}

impl Default for GosecProvider {
    fn default() -> Self {
        Self::new(GosecProviderConfig::default())
    }
}

impl GosecProvider {
    /// Create a new GosecProvider with configuration
    pub fn new(config: GosecProviderConfig) -> Self {
        let binary_path = if config.binary_path.is_empty() {
            "gosec".to_string()
        } else {
            config.binary_path.clone()
        };
        let available = Self::check_availability(&binary_path);

        if available {
            info!("gosec provider initialized successfully");
        } else {
            debug!("gosec not found - Go will use native rules only");
        }

        Self {
            binary_path,
            available,
            config,
        }
    }

    /// Check if gosec is available
    fn check_availability(binary: &str) -> bool {
        Command::new(binary)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Get gosec version if available
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

    /// Run gosec on a directory and return findings
    pub fn scan_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        if !self.available {
            warn!("gosec not available, returning empty results");
            return Ok(Vec::new());
        }

        let mut cmd = Command::new(&self.binary_path);

        // Output in JSON format
        cmd.arg("-fmt=json");

        // Add exclude rules if specified
        if !self.config.exclude_rules.is_empty() {
            cmd.arg(format!("-exclude={}", self.config.exclude_rules.join(",")));
        }

        // Add include rules if specified
        if !self.config.include_rules.is_empty() {
            cmd.arg(format!("-include={}", self.config.include_rules.join(",")));
        }

        // Add extra args
        for arg in &self.config.extra_args {
            cmd.arg(arg);
        }

        // Scan the directory recursively
        cmd.arg(format!("{}/...", path.display()));

        let output = cmd.output().context("Failed to execute gosec")?;

        // gosec returns non-zero if it finds issues
        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("issues") && !stderr.contains("Gosec") {
                debug!("gosec stderr: {}", stderr);
            }
        }

        let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in gosec output")?;

        if stdout.trim().is_empty() {
            return Ok(Vec::new());
        }

        self.parse_output(&stdout, path)
    }

    /// Run gosec on a single file
    pub fn scan_file(&self, path: &Path) -> Result<Vec<Finding>> {
        if !self.available {
            return Ok(Vec::new());
        }

        let mut cmd = Command::new(&self.binary_path);
        cmd.arg("-fmt=json");

        // Add exclude rules if specified
        if !self.config.exclude_rules.is_empty() {
            cmd.arg(format!("-exclude={}", self.config.exclude_rules.join(",")));
        }

        cmd.arg(path);

        let output = cmd.output().context("Failed to execute gosec")?;

        let stdout = String::from_utf8(output.stdout).context("Invalid UTF-8 in gosec output")?;

        if stdout.trim().is_empty() {
            return Ok(Vec::new());
        }

        self.parse_output(&stdout, path)
    }

    /// Parse gosec JSON output into RMA findings
    fn parse_output(&self, json_str: &str, base_path: &Path) -> Result<Vec<Finding>> {
        let report: GosecReport =
            serde_json::from_str(json_str).context("Failed to parse gosec JSON output")?;

        let mut findings = Vec::new();

        for issue in report.issues {
            if let Some(finding) = self.convert_issue(issue, base_path) {
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    /// Convert a gosec issue to an RMA finding
    fn convert_issue(&self, issue: GosecIssue, base_path: &Path) -> Option<Finding> {
        let severity = match issue.severity.to_uppercase().as_str() {
            "HIGH" => Severity::Critical,
            "MEDIUM" => Severity::Error,
            "LOW" => Severity::Warning,
            _ => Severity::Info,
        };

        // Map gosec rules to confidence and category
        let (confidence, category) = self.map_rule_metadata(&issue.rule_id, &issue.confidence);

        let line: usize = issue.line.parse().unwrap_or(1);
        let column: usize = issue.column.parse().unwrap_or(1);

        // Normalize path relative to base_path if possible
        let file_path = if issue.file.starts_with('/') {
            PathBuf::from(&issue.file)
        } else {
            base_path.join(&issue.file)
        };

        let rule_id = format!("gosec/{}", issue.rule_id);

        let location = SourceLocation::new(file_path.clone(), line, column, line, column);

        let mut finding = Finding {
            id: format!("{}:{}:{}", rule_id, file_path.display(), line),
            rule_id,
            message: format!("{}: {}", issue.details, issue.cwe.id),
            severity,
            location,
            language: Language::Go,
            snippet: Some(issue.code),
            suggestion: None,
            fix: None,
            confidence,
            category,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        };

        finding.compute_fingerprint();
        Some(finding)
    }

    /// Map gosec rule IDs to confidence and category
    fn map_rule_metadata(
        &self,
        rule_id: &str,
        gosec_confidence: &str,
    ) -> (Confidence, FindingCategory) {
        let confidence = match gosec_confidence.to_uppercase().as_str() {
            "HIGH" => Confidence::High,
            "MEDIUM" => Confidence::Medium,
            _ => Confidence::Low,
        };

        // Map rule IDs to categories
        let category = match rule_id {
            // SQL Injection
            "G201" | "G202" => FindingCategory::Security,
            // Command Injection
            "G204" => FindingCategory::Security,
            // File traversal
            "G304" => FindingCategory::Security,
            // File permissions
            "G301" | "G302" | "G303" | "G306" => FindingCategory::Security,
            // Crypto issues
            "G401" | "G402" | "G403" | "G404" | "G501" | "G502" | "G503" | "G504" | "G505" => {
                FindingCategory::Security
            }
            // Unsafe/Hardcoded credentials
            "G101" | "G102" | "G103" | "G104" | "G106" | "G107" | "G108" | "G109" | "G110" => {
                FindingCategory::Security
            }
            // XXE, SSRF, etc.
            "G114" => FindingCategory::Security,
            // Integer overflow
            "G115" => FindingCategory::Quality,
            // Default to security for unknown gosec rules
            _ => FindingCategory::Security,
        };

        (confidence, category)
    }
}

impl AnalysisProvider for GosecProvider {
    fn name(&self) -> &'static str {
        "gosec"
    }

    fn description(&self) -> &'static str {
        "Go Security Checker - inspects Go source code for security problems"
    }

    fn supports_language(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn version(&self) -> Option<String> {
        GosecProvider::version(self)
    }

    fn analyze_file(&self, path: &Path) -> Result<Vec<Finding>> {
        self.scan_file(path)
    }

    fn analyze_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        self.scan_directory(path)
    }
}

/// Gosec JSON report structure
#[derive(Debug, Deserialize)]
struct GosecReport {
    #[serde(rename = "Issues", default)]
    issues: Vec<GosecIssue>,
    #[serde(rename = "Stats", default)]
    _stats: Option<GosecStats>,
}

/// Individual gosec issue
#[derive(Debug, Deserialize)]
struct GosecIssue {
    /// Severity level (HIGH, MEDIUM, LOW)
    severity: String,

    /// Confidence level (HIGH, MEDIUM, LOW)
    confidence: String,

    /// CWE information
    cwe: GosecCwe,

    /// Rule ID (e.g., "G101", "G201")
    #[serde(rename = "rule_id")]
    rule_id: String,

    /// Issue details/description
    details: String,

    /// Source file path
    file: String,

    /// Source code snippet
    code: String,

    /// Line number (as string in gosec output)
    line: String,

    /// Column number (as string in gosec output)
    column: String,
}

/// CWE reference in gosec output
#[derive(Debug, Deserialize)]
struct GosecCwe {
    /// CWE ID (e.g., "CWE-89")
    #[serde(rename = "ID")]
    id: String,
}

/// Gosec statistics
#[derive(Debug, Deserialize)]
struct GosecStats {
    #[serde(default)]
    _files: usize,
    #[serde(default)]
    _lines: usize,
    #[serde(default)]
    _nosec: usize,
    #[serde(default)]
    _found: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = GosecProvider::default();
        // Just test that it doesn't panic - availability depends on system
        let _ = provider.is_available();
    }

    #[test]
    fn test_parse_json_output() {
        let provider = GosecProvider::default();

        let json = r#"{
            "Issues": [
                {
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "cwe": {"ID": "CWE-89"},
                    "rule_id": "G201",
                    "details": "SQL string formatting",
                    "file": "main.go",
                    "code": "db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", id))",
                    "line": "42",
                    "column": "10"
                }
            ],
            "Stats": {"files": 1, "lines": 100, "nosec": 0, "found": 1}
        }"#;

        let findings = provider.parse_output(json, Path::new(".")).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "gosec/G201");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].language, Language::Go);
    }

    #[test]
    fn test_severity_mapping() {
        let provider = GosecProvider::default();

        let json = r#"{
            "Issues": [
                {"severity": "HIGH", "confidence": "HIGH", "cwe": {"ID": "CWE-1"}, "rule_id": "G101", "details": "d", "file": "f", "code": "c", "line": "1", "column": "1"},
                {"severity": "MEDIUM", "confidence": "MEDIUM", "cwe": {"ID": "CWE-2"}, "rule_id": "G102", "details": "d", "file": "f", "code": "c", "line": "2", "column": "1"},
                {"severity": "LOW", "confidence": "LOW", "cwe": {"ID": "CWE-3"}, "rule_id": "G103", "details": "d", "file": "f", "code": "c", "line": "3", "column": "1"}
            ]
        }"#;

        let findings = provider.parse_output(json, Path::new(".")).unwrap();
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Error);
        assert_eq!(findings[2].severity, Severity::Warning);
    }

    #[test]
    fn test_confidence_mapping() {
        let provider = GosecProvider::default();

        let json = r#"{
            "Issues": [
                {"severity": "HIGH", "confidence": "HIGH", "cwe": {"ID": "CWE-1"}, "rule_id": "G201", "details": "d", "file": "f", "code": "c", "line": "1", "column": "1"},
                {"severity": "HIGH", "confidence": "LOW", "cwe": {"ID": "CWE-2"}, "rule_id": "G202", "details": "d", "file": "f", "code": "c", "line": "2", "column": "1"}
            ]
        }"#;

        let findings = provider.parse_output(json, Path::new(".")).unwrap();
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[1].confidence, Confidence::Low);
    }
}
