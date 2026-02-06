//! Common types and utilities for Rust Monorepo Analyzer (RMA)
//!
//! This crate provides shared data structures, error types, and utilities
//! used across all RMA components.

pub mod config;
pub mod suppression;

pub use config::{
    AllowConfig, AllowType, Baseline, BaselineConfig, BaselineEntry, BaselineMode,
    CURRENT_CONFIG_VERSION, ConfigLoadResult, ConfigSource, ConfigWarning,
    DEFAULT_EXAMPLE_IGNORE_PATHS, DEFAULT_TEST_IGNORE_PATHS, DEFAULT_VENDOR_IGNORE_PATHS,
    EffectiveConfig, Fingerprint, GosecProviderConfig, InlineSuppression, OsvEcosystem,
    OsvProviderConfig, OxcProviderConfig, OxlintProviderConfig, PmdProviderConfig, Profile,
    ProfileThresholds, ProfilesConfig, ProviderType, ProvidersConfig, RULES_ALWAYS_ENABLED,
    RmaTomlConfig, RulesConfig, RulesetsConfig, ScanConfig, SuppressionConfig, SuppressionEngine,
    SuppressionResult, SuppressionSource, SuppressionType, ThresholdOverride, WarningLevel,
    parse_expiration_days, parse_inline_suppressions,
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

/// Supported programming languages (30+ tree-sitter grammars)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    // Systems languages
    Rust,
    C,
    Cpp,
    Zig,

    // JVM languages
    Java,
    Kotlin,
    Scala,

    // Web languages
    JavaScript,
    TypeScript,
    Html,
    Css,
    Scss,
    Vue,
    Svelte,

    // Scripting languages
    Python,
    Ruby,
    Php,
    Lua,
    Perl,

    // Functional languages
    Haskell,
    OCaml,
    Elixir,
    Erlang,

    // Other compiled languages
    Go,
    Swift,
    CSharp,
    Dart,

    // Data/Config languages
    Json,
    Yaml,
    Toml,
    Sql,
    GraphQL,

    // Infrastructure
    Bash,
    Dockerfile,
    Hcl, // Terraform
    Nix,

    // Markup
    Markdown,
    Latex,

    // Other
    Solidity, // Smart contracts
    Wasm,     // WebAssembly text format
    Protobuf,

    Unknown,
}

impl Language {
    /// Detect language from file extension
    #[inline]
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            // Systems
            "rs" => Language::Rust,
            "c" | "h" => Language::C,
            "cc" | "cpp" | "cxx" | "hpp" | "hxx" | "hh" => Language::Cpp,
            "zig" => Language::Zig,

            // JVM
            "java" => Language::Java,
            "kt" | "kts" => Language::Kotlin,
            "scala" | "sc" => Language::Scala,

            // Web
            "js" | "mjs" | "cjs" | "jsx" => Language::JavaScript,
            "ts" | "tsx" | "mts" | "cts" => Language::TypeScript,
            "html" | "htm" => Language::Html,
            "css" => Language::Css,
            "scss" | "sass" => Language::Scss,
            "vue" => Language::Vue,
            "svelte" => Language::Svelte,

            // Scripting
            "py" | "pyi" | "pyw" => Language::Python,
            "rb" | "erb" | "rake" | "gemspec" => Language::Ruby,
            "php" | "phtml" | "php3" | "php4" | "php5" | "phps" => Language::Php,
            "lua" => Language::Lua,
            "pl" | "pm" | "t" => Language::Perl,

            // Functional
            "hs" | "lhs" => Language::Haskell,
            "ml" | "mli" => Language::OCaml,
            "ex" | "exs" => Language::Elixir,
            "erl" | "hrl" => Language::Erlang,

            // Other compiled
            "go" => Language::Go,
            "swift" => Language::Swift,
            "cs" | "csx" => Language::CSharp,
            "dart" => Language::Dart,

            // Data/Config
            "json" | "jsonc" | "json5" => Language::Json,
            "yaml" | "yml" => Language::Yaml,
            "toml" => Language::Toml,
            "sql" | "mysql" | "pgsql" | "plsql" => Language::Sql,
            "graphql" | "gql" => Language::GraphQL,

            // Infrastructure
            "sh" | "bash" | "zsh" | "fish" => Language::Bash,
            "dockerfile" => Language::Dockerfile,
            "tf" | "tfvars" | "hcl" => Language::Hcl,
            "nix" => Language::Nix,

            // Markup
            "md" | "markdown" | "mdx" => Language::Markdown,
            "tex" | "latex" | "sty" | "cls" => Language::Latex,

            // Other
            "sol" => Language::Solidity,
            "wat" | "wast" => Language::Wasm,
            "proto" | "proto3" => Language::Protobuf,

            _ => Language::Unknown,
        }
    }

    /// Get file extensions for this language
    #[inline]
    pub fn extensions(&self) -> &'static [&'static str] {
        match self {
            Language::Rust => &["rs"],
            Language::C => &["c", "h"],
            Language::Cpp => &["cc", "cpp", "cxx", "hpp", "hxx", "hh"],
            Language::Zig => &["zig"],
            Language::Java => &["java"],
            Language::Kotlin => &["kt", "kts"],
            Language::Scala => &["scala", "sc"],
            Language::JavaScript => &["js", "mjs", "cjs", "jsx"],
            Language::TypeScript => &["ts", "tsx", "mts", "cts"],
            Language::Html => &["html", "htm"],
            Language::Css => &["css"],
            Language::Scss => &["scss", "sass"],
            Language::Vue => &["vue"],
            Language::Svelte => &["svelte"],
            Language::Python => &["py", "pyi", "pyw"],
            Language::Ruby => &["rb", "erb", "rake", "gemspec"],
            Language::Php => &["php", "phtml"],
            Language::Lua => &["lua"],
            Language::Perl => &["pl", "pm", "t"],
            Language::Haskell => &["hs", "lhs"],
            Language::OCaml => &["ml", "mli"],
            Language::Elixir => &["ex", "exs"],
            Language::Erlang => &["erl", "hrl"],
            Language::Go => &["go"],
            Language::Swift => &["swift"],
            Language::CSharp => &["cs", "csx"],
            Language::Dart => &["dart"],
            Language::Json => &["json", "jsonc", "json5"],
            Language::Yaml => &["yaml", "yml"],
            Language::Toml => &["toml"],
            Language::Sql => &["sql", "mysql", "pgsql"],
            Language::GraphQL => &["graphql", "gql"],
            Language::Bash => &["sh", "bash", "zsh", "fish"],
            Language::Dockerfile => &["dockerfile"],
            Language::Hcl => &["tf", "tfvars", "hcl"],
            Language::Nix => &["nix"],
            Language::Markdown => &["md", "markdown", "mdx"],
            Language::Latex => &["tex", "latex", "sty", "cls"],
            Language::Solidity => &["sol"],
            Language::Wasm => &["wat", "wast"],
            Language::Protobuf => &["proto", "proto3"],
            Language::Unknown => &[],
        }
    }

    /// Check if this language is a systems language (for memory safety analysis)
    #[inline]
    pub fn is_systems_language(&self) -> bool {
        matches!(
            self,
            Language::Rust | Language::C | Language::Cpp | Language::Zig
        )
    }

    /// Check if this language is a scripting language
    #[inline]
    pub fn is_scripting_language(&self) -> bool {
        matches!(
            self,
            Language::JavaScript
                | Language::TypeScript
                | Language::Python
                | Language::Ruby
                | Language::Php
                | Language::Lua
                | Language::Perl
        )
    }

    /// Check if this language is a JVM language
    #[inline]
    pub fn is_jvm_language(&self) -> bool {
        matches!(self, Language::Java | Language::Kotlin | Language::Scala)
    }

    /// Check if this language is a functional language
    #[inline]
    pub fn is_functional_language(&self) -> bool {
        matches!(
            self,
            Language::Haskell | Language::OCaml | Language::Elixir | Language::Erlang
        )
    }

    /// Check if this language is a data/config language
    #[inline]
    pub fn is_data_language(&self) -> bool {
        matches!(
            self,
            Language::Json | Language::Yaml | Language::Toml | Language::Sql | Language::GraphQL
        )
    }

    /// Check if this language supports security scanning (has security-relevant constructs)
    #[inline]
    pub fn supports_security_scanning(&self) -> bool {
        !matches!(
            self,
            Language::Unknown | Language::Markdown | Language::Latex | Language::Wasm
        )
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::Rust => write!(f, "rust"),
            Language::C => write!(f, "c"),
            Language::Cpp => write!(f, "cpp"),
            Language::Zig => write!(f, "zig"),
            Language::Java => write!(f, "java"),
            Language::Kotlin => write!(f, "kotlin"),
            Language::Scala => write!(f, "scala"),
            Language::JavaScript => write!(f, "javascript"),
            Language::TypeScript => write!(f, "typescript"),
            Language::Html => write!(f, "html"),
            Language::Css => write!(f, "css"),
            Language::Scss => write!(f, "scss"),
            Language::Vue => write!(f, "vue"),
            Language::Svelte => write!(f, "svelte"),
            Language::Python => write!(f, "python"),
            Language::Ruby => write!(f, "ruby"),
            Language::Php => write!(f, "php"),
            Language::Lua => write!(f, "lua"),
            Language::Perl => write!(f, "perl"),
            Language::Haskell => write!(f, "haskell"),
            Language::OCaml => write!(f, "ocaml"),
            Language::Elixir => write!(f, "elixir"),
            Language::Erlang => write!(f, "erlang"),
            Language::Go => write!(f, "go"),
            Language::Swift => write!(f, "swift"),
            Language::CSharp => write!(f, "csharp"),
            Language::Dart => write!(f, "dart"),
            Language::Json => write!(f, "json"),
            Language::Yaml => write!(f, "yaml"),
            Language::Toml => write!(f, "toml"),
            Language::Sql => write!(f, "sql"),
            Language::GraphQL => write!(f, "graphql"),
            Language::Bash => write!(f, "bash"),
            Language::Dockerfile => write!(f, "dockerfile"),
            Language::Hcl => write!(f, "hcl"),
            Language::Nix => write!(f, "nix"),
            Language::Markdown => write!(f, "markdown"),
            Language::Latex => write!(f, "latex"),
            Language::Solidity => write!(f, "solidity"),
            Language::Wasm => write!(f, "wasm"),
            Language::Protobuf => write!(f, "protobuf"),
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

/// A suggested fix for a finding with precise byte offsets for auto-fix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fix {
    /// Human-readable description of the fix (e.g., "Replace yaml.load with yaml.safe_load")
    pub description: String,
    /// The replacement text to apply
    pub replacement: String,
    /// Start byte offset in the source
    pub start_byte: usize,
    /// End byte offset in the source (exclusive)
    pub end_byte: usize,
}

impl Fix {
    /// Create a new Fix with the given parameters
    pub fn new(
        description: impl Into<String>,
        replacement: impl Into<String>,
        start_byte: usize,
        end_byte: usize,
    ) -> Self {
        Self {
            description: description.into(),
            replacement: replacement.into(),
            start_byte,
            end_byte,
        }
    }
}

/// Source engine that produced a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindingSource {
    /// Built-in Semgrep-style pattern rules (compiled into binary)
    #[default]
    Builtin,
    /// CodeQL Models-as-Data generated profiles
    Codeql,
    /// Pysa taint stub generated profiles
    Pysa,
    /// OSV open-source vulnerability database
    Osv,
    /// RustSec advisory database
    Rustsec,
    /// Oxc native JS/TS linter
    Oxc,
    /// Oxlint CLI JS/TS linter
    Oxlint,
    /// PMD Java static analysis
    Pmd,
    /// Gosec Go security checker
    Gosec,
    /// Cross-file taint flow analysis
    #[serde(rename = "taint-flow")]
    TaintFlow,
    /// WASM plugin system
    Plugin,
    /// AI-powered analysis
    Ai,
}

impl std::fmt::Display for FindingSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSource::Builtin => write!(f, "builtin"),
            FindingSource::Codeql => write!(f, "codeql"),
            FindingSource::Pysa => write!(f, "pysa"),
            FindingSource::Osv => write!(f, "osv"),
            FindingSource::Rustsec => write!(f, "rustsec"),
            FindingSource::Oxc => write!(f, "oxc"),
            FindingSource::Oxlint => write!(f, "oxlint"),
            FindingSource::Pmd => write!(f, "pmd"),
            FindingSource::Gosec => write!(f, "gosec"),
            FindingSource::TaintFlow => write!(f, "taint-flow"),
            FindingSource::Plugin => write!(f, "plugin"),
            FindingSource::Ai => write!(f, "ai"),
        }
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
    /// Structured fix for auto-fix with precise byte offsets
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<Fix>,
    /// Confidence level (how certain we are this is a real issue)
    #[serde(default)]
    pub confidence: Confidence,
    /// Category of finding (security, quality, performance, style)
    #[serde(default)]
    pub category: FindingCategory,
    /// Source engine that produced this finding
    #[serde(default)]
    pub source: FindingSource,
    /// Stable fingerprint for baseline comparison (sha256 hash)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Additional properties (e.g., import_hits, import_files_sample for OSV findings)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub properties: Option<std::collections::HashMap<String, serde_json::Value>>,
    /// Number of occurrences when deduplicated (same rule in same file)
    /// None or 1 means single occurrence, >1 means multiple occurrences consolidated
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub occurrence_count: Option<usize>,
    /// Additional line numbers when occurrence_count > 1
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub additional_locations: Option<Vec<usize>>,
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

/// Deduplicate findings by grouping same rule in same file
///
/// When the same rule fires multiple times in the same file, consolidates them
/// into a single finding with `occurrence_count` set to the total count.
/// The first occurrence is kept as the representative, with additional line
/// numbers stored in `additional_locations`.
///
/// # Arguments
/// * `findings` - Vector of findings to deduplicate
///
/// # Returns
/// * Deduplicated vector of findings with occurrence counts
pub fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    use std::collections::HashMap;

    // Group by (file, rule_id)
    let mut grouped: HashMap<(String, String), Vec<Finding>> = HashMap::new();

    for finding in findings {
        let key = (
            finding.location.file.to_string_lossy().to_string(),
            finding.rule_id.clone(),
        );
        grouped.entry(key).or_default().push(finding);
    }

    // Consolidate each group
    let mut result = Vec::new();
    for ((_file, _rule_id), mut group) in grouped {
        if group.len() == 1 {
            // Single occurrence - no deduplication needed
            result.push(group.remove(0));
        } else {
            // Multiple occurrences - consolidate
            let count = group.len();

            // Sort by line number to get the first occurrence
            group.sort_by_key(|f| f.location.start_line);

            // Take the first as representative
            let mut representative = group.remove(0);

            // Collect additional line numbers
            let additional_lines: Vec<usize> =
                group.iter().map(|f| f.location.start_line).collect();

            representative.occurrence_count = Some(count);
            representative.additional_locations = Some(additional_lines);

            // Update message to indicate deduplication
            representative.message = format!(
                "{} ({} occurrences in this file)",
                representative.message, count
            );

            result.push(representative);
        }
    }

    // Sort by file and line for consistent output
    result.sort_by(|a, b| {
        let file_cmp = a.location.file.cmp(&b.location.file);
        if file_cmp == std::cmp::Ordering::Equal {
            a.location.start_line.cmp(&b.location.start_line)
        } else {
            file_cmp
        }
    });

    result
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
