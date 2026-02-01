//! Common types and utilities for Rust Monorepo Analyzer (RMA)
//!
//! This crate provides shared data structures, error types, and utilities
//! used across all RMA components.

pub mod config;
pub mod suppression;

pub use config::{
    AllowConfig, AllowType, Baseline, BaselineConfig, BaselineEntry, BaselineMode,
    CURRENT_CONFIG_VERSION, ConfigLoadResult, ConfigSource, ConfigWarning,
    DEFAULT_EXAMPLE_IGNORE_PATHS, DEFAULT_TEST_IGNORE_PATHS, EffectiveConfig, Fingerprint,
    GosecProviderConfig, InlineSuppression, OsvEcosystem, OsvProviderConfig, OxcProviderConfig,
    OxlintProviderConfig, PmdProviderConfig, Profile, ProfileThresholds, ProfilesConfig,
    ProviderType, ProvidersConfig, RULES_ALWAYS_ENABLED, RmaTomlConfig, RulesConfig,
    RulesetsConfig, ScanConfig, SuppressionConfig, SuppressionEngine, SuppressionResult,
    SuppressionSource, SuppressionType, ThresholdOverride, WarningLevel, parse_expiration_days,
    parse_inline_suppressions,
};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

/// Core error types for RMA operations
#[derive(Error, Debug)]
pub enum RmaError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error in {file}: {message}")]
    Parse { file: PathBuf, message: String },

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Index error: {0}")]
    Index(String),

    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// Supported programming languages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Rust,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Java,
    Unknown,
}

impl Language {
    /// Detect language from file extension
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "rs" => Language::Rust,
            "js" | "mjs" | "cjs" => Language::JavaScript,
            "ts" | "tsx" => Language::TypeScript,
            "py" | "pyi" => Language::Python,
            "go" => Language::Go,
            "java" => Language::Java,
            _ => Language::Unknown,
        }
    }

    /// Get file extensions for this language
    pub fn extensions(&self) -> &'static [&'static str] {
        match self {
            Language::Rust => &["rs"],
            Language::JavaScript => &["js", "mjs", "cjs"],
            Language::TypeScript => &["ts", "tsx"],
            Language::Python => &["py", "pyi"],
            Language::Go => &["go"],
            Language::Java => &["java"],
            Language::Unknown => &[],
        }
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::Rust => write!(f, "rust"),
            Language::JavaScript => write!(f, "javascript"),
            Language::TypeScript => write!(f, "typescript"),
            Language::Python => write!(f, "python"),
            Language::Go => write!(f, "go"),
            Language::Java => write!(f, "java"),
            Language::Unknown => write!(f, "unknown"),
        }
    }
}

/// Severity levels for findings
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    #[default]
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Confidence level for findings (how certain we are this is a real issue)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Low confidence - may be a false positive, requires manual review
    Low,
    /// Medium confidence - likely an issue but context-dependent
    #[default]
    Medium,
    /// High confidence - almost certainly a real issue
    High,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Low => write!(f, "low"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::High => write!(f, "high"),
        }
    }
}

/// Category of finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindingCategory {
    /// Security vulnerabilities
    #[default]
    Security,
    /// Code quality and maintainability
    Quality,
    /// Performance issues
    Performance,
    /// Style and formatting
    Style,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::Security => write!(f, "security"),
            FindingCategory::Quality => write!(f, "quality"),
            FindingCategory::Performance => write!(f, "performance"),
            FindingCategory::Style => write!(f, "style"),
        }
    }
}

/// A source code location
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: PathBuf,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

impl SourceLocation {
    pub fn new(
        file: PathBuf,
        start_line: usize,
        start_column: usize,
        end_line: usize,
        end_column: usize,
    ) -> Self {
        Self {
            file,
            start_line,
            start_column,
            end_line,
            end_column,
        }
    }
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}-{}:{}",
            self.file.display(),
            self.start_line,
            self.start_column,
            self.end_line,
            self.end_column
        )
    }
}

/// A security or code quality finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub message: String,
    pub severity: Severity,
    pub location: SourceLocation,
    pub language: Language,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    /// Confidence level (how certain we are this is a real issue)
    #[serde(default)]
    pub confidence: Confidence,
    /// Category of finding (security, quality, performance, style)
    #[serde(default)]
    pub category: FindingCategory,
    /// Stable fingerprint for baseline comparison (sha256 hash)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Additional properties (e.g., import_hits, import_files_sample for OSV findings)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub properties: Option<std::collections::HashMap<String, serde_json::Value>>,
}

impl Finding {
    /// Compute a stable fingerprint for this finding
    /// Based on: rule_id + relative path + normalized snippet
    pub fn compute_fingerprint(&mut self) {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.rule_id.as_bytes());
        hasher.update(self.location.file.to_string_lossy().as_bytes());

        // Normalize snippet by removing whitespace
        if let Some(snippet) = &self.snippet {
            let normalized: String = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
            hasher.update(normalized.as_bytes());
        }

        let hash = hasher.finalize();
        self.fingerprint = Some(format!("sha256:{:x}", hash)[..23].to_string());
    }
}

/// Code metrics for a file or function
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CodeMetrics {
    pub lines_of_code: usize,
    pub lines_of_comments: usize,
    pub blank_lines: usize,
    pub cyclomatic_complexity: usize,
    pub cognitive_complexity: usize,
    pub function_count: usize,
    pub class_count: usize,
    pub import_count: usize,
}

/// Summary of a scan operation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub total_lines: usize,
    pub findings_by_severity: std::collections::HashMap<String, usize>,
    pub languages: std::collections::HashMap<String, usize>,
    pub duration_ms: u64,
}

/// Configuration for RMA operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RmaConfig {
    /// Paths to exclude from scanning
    #[serde(default)]
    pub exclude_patterns: Vec<String>,

    /// Languages to scan (empty = all supported)
    #[serde(default)]
    pub languages: Vec<Language>,

    /// Minimum severity to report
    #[serde(default = "default_min_severity")]
    pub min_severity: Severity,

    /// Maximum file size in bytes
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,

    /// Number of parallel workers (0 = auto)
    #[serde(default)]
    pub parallelism: usize,

    /// Enable incremental mode
    #[serde(default)]
    pub incremental: bool,
}

fn default_min_severity() -> Severity {
    Severity::Warning
}

fn default_max_file_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

impl Default for RmaConfig {
    fn default() -> Self {
        Self {
            exclude_patterns: vec![
                "**/node_modules/**".into(),
                "**/target/**".into(),
                "**/vendor/**".into(),
                "**/.git/**".into(),
                "**/dist/**".into(),
                "**/build/**".into(),
            ],
            languages: vec![],
            min_severity: default_min_severity(),
            max_file_size: default_max_file_size(),
            parallelism: 0,
            incremental: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_from_extension() {
        assert_eq!(Language::from_extension("rs"), Language::Rust);
        assert_eq!(Language::from_extension("js"), Language::JavaScript);
        assert_eq!(Language::from_extension("py"), Language::Python);
        assert_eq!(Language::from_extension("unknown"), Language::Unknown);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn test_source_location_display() {
        let loc = SourceLocation::new(PathBuf::from("test.rs"), 10, 5, 10, 15);
        assert_eq!(loc.to_string(), "test.rs:10:5-10:15");
    }
}
