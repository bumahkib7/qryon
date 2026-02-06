//! PMD provider for Java static analysis
//!
//! Integrates with [PMD](https://pmd.github.io/), a source code analyzer for
//! Java, JavaScript, and other languages with comprehensive security and
//! quality rules.
//!
//! This provider shells out to the PMD CLI and parses its XML output,
//! converting findings to RMA's unified Finding format.
//!
//! # PMD Priority to RMA Severity Mapping
//!
//! PMD uses priority levels 1-5 (1 = highest):
//! - Priority 1: Critical
//! - Priority 2: Error
//! - Priority 3: Warning
//! - Priority 4-5: Info

use super::AnalysisProvider;
use anyhow::{Context, Result};
use quick_xml::de::from_str;
use rma_common::{
    Confidence, Finding, FindingCategory, FindingSource, Language, Severity, SourceLocation,
    config::PmdProviderConfig,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// PMD Java analysis provider
pub struct PmdProvider {
    config: PmdProviderConfig,
    available: bool,
    pmd_command: String,
}

impl Default for PmdProvider {
    fn default() -> Self {
        Self::new(PmdProviderConfig::default())
    }
}

impl PmdProvider {
    /// Create a new PMD provider with the given configuration
    pub fn new(config: PmdProviderConfig) -> Self {
        let (available, pmd_command) = Self::find_pmd(&config);

        if available {
            info!("PMD provider initialized: {}", pmd_command);
        } else {
            debug!("PMD not found - Java will use native rules only");
        }

        Self {
            config,
            available,
            pmd_command,
        }
    }

    /// Try to find PMD installation
    fn find_pmd(config: &PmdProviderConfig) -> (bool, String) {
        // If explicit path provided, use it
        if !config.pmd_path.is_empty() {
            let path = Path::new(&config.pmd_path);
            if path.exists() {
                // Check if it's a binary or a directory
                if path.is_file() {
                    return (
                        Self::check_pmd_binary(&config.pmd_path),
                        config.pmd_path.clone(),
                    );
                } else if path.is_dir() {
                    // Look for pmd binary in bin/ subdirectory
                    let pmd_bin = path.join("bin").join("pmd");
                    if pmd_bin.exists() {
                        let pmd_path = pmd_bin.to_string_lossy().to_string();
                        return (Self::check_pmd_binary(&pmd_path), pmd_path);
                    }
                    // Or it might be the lib directory with jar
                    let pmd_jar = path.join("lib").join("pmd-dist.jar");
                    if pmd_jar.exists() {
                        return (true, format!("java -jar {}", pmd_jar.display()));
                    }
                }
            }
        }

        // Try 'pmd' in PATH
        if Self::check_pmd_binary("pmd") {
            return (true, "pmd".to_string());
        }

        // Try common locations
        let common_paths = ["/usr/local/bin/pmd", "/opt/pmd/bin/pmd", "~/.local/bin/pmd"];

        for path in common_paths {
            let expanded = shellexpand::tilde(path).to_string();
            if Path::new(&expanded).exists() && Self::check_pmd_binary(&expanded) {
                return (true, expanded);
            }
        }

        (false, String::new())
    }

    /// Check if a PMD binary works
    fn check_pmd_binary(path: &str) -> bool {
        // Handle "java -jar ..." case
        if path.starts_with("java") {
            let parts: Vec<&str> = path.split_whitespace().collect();
            if parts.len() >= 3 {
                return Command::new(parts[0])
                    .args(&parts[1..])
                    .arg("--version")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
            }
        }

        Command::new(path)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Build the PMD command arguments
    fn build_command(&self, target_path: &Path) -> Vec<String> {
        let mut args = vec![
            "check".to_string(),
            "-d".to_string(),
            target_path.to_string_lossy().to_string(),
            "-f".to_string(),
            "xml".to_string(),
        ];

        // Add rulesets
        if !self.config.rulesets.is_empty() {
            args.push("-R".to_string());
            args.push(self.config.rulesets.join(","));
        }

        // Add minimum priority filter
        if self.config.min_priority < 5 {
            args.push("--minimum-priority".to_string());
            args.push(self.config.min_priority.to_string());
        }

        // Add extra arguments
        args.extend(self.config.extra_args.clone());

        args
    }

    /// Run PMD and return findings
    pub fn run_pmd(&self, path: &Path) -> Result<Vec<Finding>> {
        if !self.available {
            if self.config.fail_on_error {
                anyhow::bail!("PMD is not available");
            }
            warn!("PMD not available, returning empty results");
            return Ok(Vec::new());
        }

        let args = self.build_command(path);
        debug!("Running PMD: {} {:?}", self.pmd_command, args);

        // Parse command (might be "java -jar path" or just "pmd")
        let (program, full_args) = if self.pmd_command.starts_with("java") {
            let parts: Vec<&str> = self.pmd_command.split_whitespace().collect();
            let program = parts[0].to_string();
            let mut cmd_args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
            cmd_args.extend(args);
            (program, cmd_args)
        } else {
            (self.pmd_command.clone(), args)
        };

        // Run with timeout
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let (tx, rx) = mpsc::channel();

        let program_clone = program.clone();
        let args_clone = full_args.clone();

        let handle = std::thread::spawn(move || {
            let output = Command::new(&program_clone)
                .args(&args_clone)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output();
            let _ = tx.send(output);
        });

        match rx.recv_timeout(timeout) {
            Ok(output_result) => {
                let _ = handle.join();
                let output = output_result.context("Failed to execute PMD")?;

                // PMD returns non-zero if it finds violations, so we check stderr for errors
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.is_empty() && !stderr.contains("violations") {
                    debug!("PMD stderr: {}", stderr);
                }

                let stdout =
                    String::from_utf8(output.stdout).context("Invalid UTF-8 in PMD output")?;

                if stdout.trim().is_empty() {
                    return Ok(Vec::new());
                }

                self.parse_xml_output(&stdout, path)
            }
            Err(_) => {
                // Timeout - try to kill the process
                warn!("PMD execution timed out after {:?}", timeout);
                if self.config.fail_on_error {
                    anyhow::bail!("PMD execution timed out");
                }
                Ok(Vec::new())
            }
        }
    }

    /// Parse PMD XML output into RMA findings
    fn parse_xml_output(&self, xml: &str, base_path: &Path) -> Result<Vec<Finding>> {
        // Try to parse as PMD XML format
        let pmd_report: PmdReport = from_str(xml).context("Failed to parse PMD XML output")?;

        let mut findings = Vec::new();

        for file in pmd_report.files {
            for violation in file.violations {
                if let Some(finding) = self.convert_violation(&file.name, &violation, base_path) {
                    findings.push(finding);
                }
            }
        }

        info!("PMD found {} findings", findings.len());
        Ok(findings)
    }

    /// Convert a PMD violation to an RMA Finding
    fn convert_violation(
        &self,
        filename: &str,
        violation: &PmdViolation,
        _base_path: &Path,
    ) -> Option<Finding> {
        // Map priority to severity using config or defaults
        let priority_str = violation.priority.to_string();
        let severity = self
            .config
            .severity_map
            .get(&priority_str)
            .copied()
            .unwrap_or_else(|| Self::default_severity(violation.priority));

        // Determine confidence based on rule category
        let (confidence, category) = Self::categorize_rule(&violation.rule, &violation.ruleset);

        let rule_id = format!("pmd/java/{}", violation.rule);

        let location = SourceLocation::new(
            PathBuf::from(filename),
            violation.begin_line,
            violation.begin_column.unwrap_or(1),
            violation.end_line.unwrap_or(violation.begin_line),
            violation.end_column.unwrap_or(1),
        );

        let mut finding = Finding {
            id: format!("{}:{}:{}", rule_id, filename, violation.begin_line),
            rule_id,
            message: violation.message.trim().to_string(),
            severity,
            location,
            language: Language::Java,
            snippet: None, // PMD doesn't include snippet in XML
            suggestion: violation.external_info_url.clone(),
            fix: None,
            confidence,
            category,
            source: FindingSource::Pmd,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        };

        finding.compute_fingerprint();
        Some(finding)
    }

    /// Default severity mapping for PMD priority
    fn default_severity(priority: u8) -> Severity {
        match priority {
            1 => Severity::Critical,
            2 => Severity::Error,
            3 => Severity::Warning,
            _ => Severity::Info,
        }
    }

    /// Categorize rule based on ruleset and rule name
    fn categorize_rule(rule: &str, ruleset: &str) -> (Confidence, FindingCategory) {
        let ruleset_lower = ruleset.to_lowercase();
        let rule_lower = rule.to_lowercase();

        // Security rules
        if ruleset_lower.contains("security")
            || rule_lower.contains("injection")
            || rule_lower.contains("xss")
            || rule_lower.contains("crypto")
            || rule_lower.contains("sensitive")
            || rule_lower.contains("hardcoded")
        {
            return (Confidence::High, FindingCategory::Security);
        }

        // Error-prone / correctness rules
        if ruleset_lower.contains("errorprone")
            || ruleset_lower.contains("error-prone")
            || rule_lower.contains("null")
            || rule_lower.contains("exception")
            || rule_lower.contains("resource")
        {
            return (Confidence::Medium, FindingCategory::Quality);
        }

        // Best practices
        if ruleset_lower.contains("bestpractices") || ruleset_lower.contains("best-practices") {
            return (Confidence::Medium, FindingCategory::Quality);
        }

        // Performance
        if ruleset_lower.contains("performance") || rule_lower.contains("performance") {
            return (Confidence::Medium, FindingCategory::Performance);
        }

        // Design / code style
        if ruleset_lower.contains("design")
            || ruleset_lower.contains("code")
            || ruleset_lower.contains("style")
        {
            return (Confidence::Low, FindingCategory::Style);
        }

        // Default
        (Confidence::Medium, FindingCategory::Quality)
    }

    /// Check if a file should be included based on patterns
    fn should_include_file(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check exclude patterns first
        for pattern in &self.config.exclude_patterns {
            if Self::matches_glob(&path_str, pattern) {
                return false;
            }
        }

        // Check include patterns
        for pattern in &self.config.include_patterns {
            if Self::matches_glob(&path_str, pattern) {
                return true;
            }
        }

        // Default: include .java files
        path.extension().map(|ext| ext == "java").unwrap_or(false)
    }

    /// Simple glob matching
    fn matches_glob(path: &str, pattern: &str) -> bool {
        let regex_pattern = pattern
            .replace("**", "§")
            .replace('*', "[^/]*")
            .replace('§', ".*");

        regex::Regex::new(&format!("^{}$", regex_pattern))
            .map(|re| re.is_match(path))
            .unwrap_or(false)
    }
}

impl AnalysisProvider for PmdProvider {
    fn name(&self) -> &'static str {
        "pmd"
    }

    fn description(&self) -> &'static str {
        "PMD Java static analysis for security and quality"
    }

    fn supports_language(&self, lang: Language) -> bool {
        // PMD primarily supports Java, but also JavaScript
        // We focus on Java here as that's the main use case
        matches!(lang, Language::Java)
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn version(&self) -> Option<String> {
        if !self.available {
            return None;
        }

        let (program, args) = if self.pmd_command.starts_with("java") {
            let parts: Vec<&str> = self.pmd_command.split_whitespace().collect();
            (
                parts[0].to_string(),
                parts[1..].iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        } else {
            (self.pmd_command.clone(), Vec::new())
        };

        let mut cmd = Command::new(&program);
        cmd.args(&args).arg("--version");

        cmd.output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    }

    fn analyze_file(&self, path: &Path) -> Result<Vec<Finding>> {
        if !self.should_include_file(path) {
            return Ok(Vec::new());
        }
        self.run_pmd(path)
    }

    fn analyze_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        self.run_pmd(path)
    }

    fn analyze_files(&self, files: &[&Path]) -> Result<Vec<Finding>> {
        // Filter to Java files only
        let java_files: Vec<_> = files
            .iter()
            .filter(|f| self.should_include_file(f))
            .collect();

        if java_files.is_empty() {
            return Ok(Vec::new());
        }

        // PMD can analyze multiple files, but for simplicity we use directory mode
        // A more efficient implementation would create a file list for PMD
        let mut all_findings = Vec::new();
        for file in java_files {
            let findings = self.run_pmd(file)?;
            all_findings.extend(findings);
        }
        Ok(all_findings)
    }
}

// =============================================================================
// PMD XML Report Structures
// =============================================================================

/// Root element of PMD XML report
#[derive(Debug, Deserialize)]
#[serde(rename = "pmd")]
struct PmdReport {
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<String>,

    #[serde(rename = "file", default)]
    files: Vec<PmdFile>,
}

/// File element containing violations
#[derive(Debug, Deserialize)]
struct PmdFile {
    #[serde(rename = "@name")]
    name: String,

    #[serde(rename = "violation", default)]
    violations: Vec<PmdViolation>,
}

/// Individual PMD violation
#[derive(Debug, Deserialize)]
struct PmdViolation {
    /// Beginning line number
    #[serde(rename = "@beginline")]
    begin_line: usize,

    /// Ending line number
    #[serde(rename = "@endline")]
    end_line: Option<usize>,

    /// Beginning column
    #[serde(rename = "@begincolumn")]
    begin_column: Option<usize>,

    /// Ending column
    #[serde(rename = "@endcolumn")]
    end_column: Option<usize>,

    /// Rule name
    #[serde(rename = "@rule")]
    rule: String,

    /// Ruleset name
    #[serde(rename = "@ruleset")]
    ruleset: String,

    /// Priority (1-5, 1 is highest)
    #[serde(rename = "@priority")]
    priority: u8,

    /// Optional external info URL
    #[serde(rename = "@externalInfoUrl")]
    external_info_url: Option<String>,

    /// Violation message (element text)
    #[serde(rename = "$text")]
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = PmdProvider::default();
        // Just test that it doesn't panic
        let _ = provider.is_available();
    }

    #[test]
    fn test_parse_pmd_xml() {
        let provider = PmdProvider::default();

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<pmd version="6.55.0">
    <file name="/src/main/java/Example.java">
        <violation beginline="10" endline="10" begincolumn="5" endcolumn="20"
                   rule="UnusedLocalVariable" ruleset="Best Practices"
                   priority="3" externalInfoUrl="https://pmd.github.io/...">
            Avoid unused local variables such as 'temp'.
        </violation>
        <violation beginline="25" endline="30" begincolumn="1"
                   rule="AvoidReassigningParameters" ruleset="Best Practices"
                   priority="2">
            Avoid reassigning parameters such as 'input'.
        </violation>
    </file>
    <file name="/src/main/java/Security.java">
        <violation beginline="15" endline="15" begincolumn="10"
                   rule="HardcodedPassword" ruleset="Security"
                   priority="1">
            Hardcoded password detected.
        </violation>
    </file>
</pmd>"#;

        let findings = provider
            .parse_xml_output(xml, Path::new("/project"))
            .unwrap();

        assert_eq!(findings.len(), 3);

        // First finding - UnusedLocalVariable
        assert_eq!(findings[0].rule_id, "pmd/java/UnusedLocalVariable");
        assert_eq!(findings[0].severity, Severity::Warning); // priority 3
        assert_eq!(findings[0].location.start_line, 10);

        // Second finding - AvoidReassigningParameters
        assert_eq!(findings[1].rule_id, "pmd/java/AvoidReassigningParameters");
        assert_eq!(findings[1].severity, Severity::Error); // priority 2

        // Third finding - HardcodedPassword (security)
        assert_eq!(findings[2].rule_id, "pmd/java/HardcodedPassword");
        assert_eq!(findings[2].severity, Severity::Critical); // priority 1
        assert_eq!(findings[2].category, FindingCategory::Security);
        assert_eq!(findings[2].confidence, Confidence::High);
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(PmdProvider::default_severity(1), Severity::Critical);
        assert_eq!(PmdProvider::default_severity(2), Severity::Error);
        assert_eq!(PmdProvider::default_severity(3), Severity::Warning);
        assert_eq!(PmdProvider::default_severity(4), Severity::Info);
        assert_eq!(PmdProvider::default_severity(5), Severity::Info);
    }

    #[test]
    fn test_rule_categorization() {
        // Security rules
        let (conf, cat) = PmdProvider::categorize_rule("HardcodedPassword", "Security");
        assert_eq!(conf, Confidence::High);
        assert_eq!(cat, FindingCategory::Security);

        // Error-prone rules
        let (conf, cat) = PmdProvider::categorize_rule("NullAssignment", "Error Prone");
        assert_eq!(conf, Confidence::Medium);
        assert_eq!(cat, FindingCategory::Quality);

        // Performance rules
        let (conf, cat) =
            PmdProvider::categorize_rule("UseStringBufferForStringAppends", "Performance");
        assert_eq!(conf, Confidence::Medium);
        assert_eq!(cat, FindingCategory::Performance);

        // Design rules
        let (conf, cat) = PmdProvider::categorize_rule("TooManyMethods", "Design");
        assert_eq!(conf, Confidence::Low);
        assert_eq!(cat, FindingCategory::Style);
    }

    #[test]
    fn test_glob_matching() {
        assert!(PmdProvider::matches_glob(
            "/src/main/java/Test.java",
            "**/*.java"
        ));
        assert!(PmdProvider::matches_glob(
            "/target/classes/Test.java",
            "**/target/**"
        ));
        assert!(!PmdProvider::matches_glob(
            "/src/main/java/Test.java",
            "**/target/**"
        ));
    }

    #[test]
    fn test_file_inclusion() {
        let provider = PmdProvider::default();

        // Should include .java files
        assert!(provider.should_include_file(Path::new("/src/Main.java")));

        // Should exclude target directory
        assert!(!provider.should_include_file(Path::new("/target/classes/Main.java")));

        // Should exclude non-Java files
        assert!(!provider.should_include_file(Path::new("/src/main.rs")));
    }

    #[test]
    fn test_empty_xml() {
        let provider = PmdProvider::default();

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<pmd version="6.55.0">
</pmd>"#;

        let findings = provider
            .parse_xml_output(xml, Path::new("/project"))
            .unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_command_building() {
        let config = PmdProviderConfig {
            rulesets: vec![
                "category/java/security.xml".to_string(),
                "category/java/bestpractices.xml".to_string(),
            ],
            ..Default::default()
        };

        let provider = PmdProvider::new(config);
        let args = provider.build_command(Path::new("/project"));

        assert!(args.contains(&"check".to_string()));
        assert!(args.contains(&"-d".to_string()));
        assert!(args.contains(&"/project".to_string()));
        assert!(args.contains(&"-f".to_string()));
        assert!(args.contains(&"xml".to_string()));
        assert!(args.contains(&"-R".to_string()));
    }
}
