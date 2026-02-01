//! Enterprise configuration system for RMA
//!
//! Supports:
//! - Local config file: rma.toml in repo root or .rma/rma.toml
//! - Profiles: fast, balanced, strict
//! - Rule enable/disable, severity overrides, threshold overrides
//! - Path-specific overrides
//! - Allowlists for approved patterns
//! - Baseline mode for legacy debt management

use crate::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Profile presets for quick configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Fast scanning with relaxed thresholds
    Fast,
    /// Balanced defaults suitable for most projects
    #[default]
    Balanced,
    /// Strict mode for high-quality codebases
    Strict,
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Profile::Fast => write!(f, "fast"),
            Profile::Balanced => write!(f, "balanced"),
            Profile::Strict => write!(f, "strict"),
        }
    }
}

impl std::str::FromStr for Profile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fast" => Ok(Profile::Fast),
            "balanced" => Ok(Profile::Balanced),
            "strict" => Ok(Profile::Strict),
            _ => Err(format!(
                "Unknown profile: {}. Use: fast, balanced, strict",
                s
            )),
        }
    }
}

/// Baseline mode for handling legacy code
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BaselineMode {
    /// Report all findings
    #[default]
    All,
    /// Only report new findings not in baseline
    NewOnly,
}

/// Scan path configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanConfig {
    /// Glob patterns to include (default: all supported files)
    #[serde(default)]
    pub include: Vec<String>,

    /// Glob patterns to exclude
    #[serde(default)]
    pub exclude: Vec<String>,

    /// Maximum file size in bytes (default: 10MB)
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,
}

fn default_max_file_size() -> usize {
    10 * 1024 * 1024
}

/// Rule configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesConfig {
    /// Rules to enable (supports wildcards like "security/*")
    #[serde(default = "default_enable")]
    pub enable: Vec<String>,

    /// Rules to disable (takes precedence over enable)
    #[serde(default)]
    pub disable: Vec<String>,

    /// Global ignore paths - findings in these paths are suppressed for all rules
    /// Supports glob patterns (e.g., "**/tests/**", "**/examples/**")
    #[serde(default)]
    pub ignore_paths: Vec<String>,

    /// Per-rule ignore paths - findings for specific rules in these paths are suppressed
    /// Maps rule_id or pattern to a list of glob patterns
    /// e.g., "generic/long-function" -> ["**/tests/**", "**/examples/**"]
    #[serde(default)]
    pub ignore_paths_by_rule: HashMap<String, Vec<String>>,
}

/// Default ignore path presets for common test/example directories
/// Used automatically in --mode pr and --mode ci unless overridden
pub const DEFAULT_TEST_IGNORE_PATHS: &[&str] = &[
    "**/test/**",
    "**/tests/**",
    "**/testing/**",
    "**/__tests__/**",
    "**/__test__/**",
    "**/*.test.ts",
    "**/*.test.js",
    "**/*.test.tsx",
    "**/*.test.jsx",
    "**/*.spec.ts",
    "**/*.spec.js",
    "**/*.spec.tsx",
    "**/*.spec.jsx",
    "**/test_*.py",
    "**/*_test.py",
    "**/tests_*.py",
    "**/*_test.go",
    "**/*_test.rs",
];

/// Default ignore paths for examples/fixtures (less strict rules)
pub const DEFAULT_EXAMPLE_IGNORE_PATHS: &[&str] = &[
    "**/examples/**",
    "**/example/**",
    "**/fixtures/**",
    "**/fixture/**",
    "**/testdata/**",
    "**/test_data/**",
    "**/demo/**",
    "**/demos/**",
    "**/mocks/**",
    "**/mock/**",
    "**/__mocks__/**",
    "**/stubs/**",
];

/// Rules that should NOT be suppressed in test/example paths
/// Security rules should still fire in tests to catch issues
pub const RULES_ALWAYS_ENABLED: &[&str] = &[
    "rust/command-injection",
    "python/shell-injection",
    "go/command-injection",
    "java/command-execution",
    "js/dynamic-code-execution",
    "generic/hardcoded-secret",
];

/// Ruleset configuration - named groups of rules
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesetsConfig {
    /// Security-focused rules
    #[serde(default)]
    pub security: Vec<String>,

    /// Maintainability-focused rules
    #[serde(default)]
    pub maintainability: Vec<String>,

    /// Custom rulesets defined by user
    #[serde(flatten)]
    pub custom: HashMap<String, Vec<String>>,
}

fn default_enable() -> Vec<String> {
    vec!["*".to_string()]
}

/// Profile-specific thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileThresholds {
    /// Maximum lines per function
    #[serde(default = "default_max_function_lines")]
    pub max_function_lines: usize,

    /// Maximum cyclomatic complexity
    #[serde(default = "default_max_complexity")]
    pub max_complexity: usize,

    /// Maximum cognitive complexity
    #[serde(default = "default_max_cognitive_complexity")]
    pub max_cognitive_complexity: usize,

    /// Maximum file lines
    #[serde(default = "default_max_file_lines")]
    pub max_file_lines: usize,
}

fn default_max_function_lines() -> usize {
    100
}

fn default_max_complexity() -> usize {
    15
}

fn default_max_cognitive_complexity() -> usize {
    20
}

fn default_max_file_lines() -> usize {
    1000
}

impl Default for ProfileThresholds {
    fn default() -> Self {
        Self {
            max_function_lines: default_max_function_lines(),
            max_complexity: default_max_complexity(),
            max_cognitive_complexity: default_max_cognitive_complexity(),
            max_file_lines: default_max_file_lines(),
        }
    }
}

impl ProfileThresholds {
    /// Get thresholds for a specific profile
    pub fn for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Fast => Self {
                max_function_lines: 200,
                max_complexity: 25,
                max_cognitive_complexity: 35,
                max_file_lines: 2000,
            },
            Profile::Balanced => Self::default(),
            Profile::Strict => Self {
                max_function_lines: 50,
                max_complexity: 10,
                max_cognitive_complexity: 15,
                max_file_lines: 500,
            },
        }
    }
}

/// All profiles configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProfilesConfig {
    /// Default profile to use
    #[serde(default)]
    pub default: Profile,

    /// Fast profile thresholds
    #[serde(default = "fast_profile_defaults")]
    pub fast: ProfileThresholds,

    /// Balanced profile thresholds
    #[serde(default)]
    pub balanced: ProfileThresholds,

    /// Strict profile thresholds
    #[serde(default = "strict_profile_defaults")]
    pub strict: ProfileThresholds,
}

fn fast_profile_defaults() -> ProfileThresholds {
    ProfileThresholds::for_profile(Profile::Fast)
}

fn strict_profile_defaults() -> ProfileThresholds {
    ProfileThresholds::for_profile(Profile::Strict)
}

impl ProfilesConfig {
    /// Get thresholds for the specified profile
    pub fn get_thresholds(&self, profile: Profile) -> &ProfileThresholds {
        match profile {
            Profile::Fast => &self.fast,
            Profile::Balanced => &self.balanced,
            Profile::Strict => &self.strict,
        }
    }
}

/// Path-specific threshold overrides
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdOverride {
    /// Glob pattern for paths this override applies to
    pub path: String,

    /// Maximum function lines (optional)
    #[serde(default)]
    pub max_function_lines: Option<usize>,

    /// Maximum complexity (optional)
    #[serde(default)]
    pub max_complexity: Option<usize>,

    /// Maximum cognitive complexity (optional)
    #[serde(default)]
    pub max_cognitive_complexity: Option<usize>,

    /// Rules to disable for these paths
    #[serde(default)]
    pub disable_rules: Vec<String>,
}

/// Allowlist configuration for approved patterns
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowConfig {
    /// Allow setTimeout with string argument
    #[serde(default)]
    pub settimeout_string: bool,

    /// Allow setTimeout with function argument
    #[serde(default = "default_true")]
    pub settimeout_function: bool,

    /// Paths where innerHTML is allowed
    #[serde(default)]
    pub innerhtml_paths: Vec<String>,

    /// Paths where eval is allowed (e.g., build tools)
    #[serde(default)]
    pub eval_paths: Vec<String>,

    /// Paths where unsafe Rust is allowed
    #[serde(default)]
    pub unsafe_rust_paths: Vec<String>,

    /// Approved secret patterns (regex)
    #[serde(default)]
    pub approved_secrets: Vec<String>,
}

fn default_true() -> bool {
    true
}

// =============================================================================
// PROVIDERS CONFIGURATION
// =============================================================================

/// Available analysis providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    /// Built-in RMA rules (always available)
    Rma,
    /// PMD for Java analysis (optional)
    Pmd,
    /// Oxlint for JavaScript/TypeScript via external binary (optional)
    Oxlint,
    /// Native Oxc for JavaScript/TypeScript via Rust crates (optional)
    Oxc,
    /// RustSec for Rust dependency vulnerabilities (optional)
    RustSec,
    /// Gosec for Go security analysis (optional)
    Gosec,
    /// OSV for multi-language dependency vulnerability scanning (optional)
    Osv,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::Rma => write!(f, "rma"),
            ProviderType::Pmd => write!(f, "pmd"),
            ProviderType::Oxlint => write!(f, "oxlint"),
            ProviderType::Oxc => write!(f, "oxc"),
            ProviderType::RustSec => write!(f, "rustsec"),
            ProviderType::Gosec => write!(f, "gosec"),
            ProviderType::Osv => write!(f, "osv"),
        }
    }
}

impl std::str::FromStr for ProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "rma" => Ok(ProviderType::Rma),
            "pmd" => Ok(ProviderType::Pmd),
            "oxlint" => Ok(ProviderType::Oxlint),
            "oxc" => Ok(ProviderType::Oxc),
            "rustsec" => Ok(ProviderType::RustSec),
            "gosec" => Ok(ProviderType::Gosec),
            "osv" => Ok(ProviderType::Osv),
            _ => Err(format!(
                "Unknown provider: {}. Available: rma, pmd, oxlint, oxc, rustsec, gosec, osv",
                s
            )),
        }
    }
}

/// Providers configuration section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvidersConfig {
    /// List of enabled providers (default: ["rma"])
    #[serde(default = "default_enabled_providers")]
    pub enabled: Vec<ProviderType>,

    /// PMD provider configuration
    #[serde(default)]
    pub pmd: PmdProviderConfig,

    /// Oxlint provider configuration (external binary)
    #[serde(default)]
    pub oxlint: OxlintProviderConfig,

    /// Native Oxc provider configuration (Rust crates)
    #[serde(default)]
    pub oxc: OxcProviderConfig,

    /// Gosec provider configuration
    #[serde(default)]
    pub gosec: GosecProviderConfig,

    /// OSV provider configuration (multi-language dependency vulnerabilities)
    #[serde(default)]
    pub osv: OsvProviderConfig,
}

impl Default for ProvidersConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled_providers(),
            pmd: PmdProviderConfig::default(),
            oxlint: OxlintProviderConfig::default(),
            oxc: OxcProviderConfig::default(),
            gosec: GosecProviderConfig::default(),
            osv: OsvProviderConfig::default(),
        }
    }
}

fn default_enabled_providers() -> Vec<ProviderType> {
    // Rma: built-in rules for all languages
    // Oxc: native JS/TS linting (no external binary required)
    vec![ProviderType::Rma, ProviderType::Oxc]
}

/// PMD Java provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmdProviderConfig {
    /// Whether PMD provider is configured (separate from enabled list)
    #[serde(default)]
    pub configured: bool,

    /// Path to Java executable
    #[serde(default = "default_java_path")]
    pub java_path: String,

    /// Path to PMD installation (either pmd binary or pmd-dist directory)
    /// If empty, will try to find 'pmd' in PATH
    #[serde(default)]
    pub pmd_path: String,

    /// PMD rulesets to use
    #[serde(default = "default_pmd_rulesets")]
    pub rulesets: Vec<String>,

    /// Timeout for PMD execution in milliseconds
    #[serde(default = "default_pmd_timeout")]
    pub timeout_ms: u64,

    /// File patterns to include for PMD analysis
    #[serde(default = "default_pmd_include_patterns")]
    pub include_patterns: Vec<String>,

    /// File patterns to exclude from PMD analysis
    #[serde(default = "default_pmd_exclude_patterns")]
    pub exclude_patterns: Vec<String>,

    /// Severity mapping from PMD priority to RMA severity
    /// Keys: "1", "2", "3", "4", "5" (PMD priorities)
    /// Values: "critical", "error", "warning", "info"
    #[serde(default = "default_pmd_severity_map")]
    pub severity_map: HashMap<String, Severity>,

    /// Whether to fail the scan if PMD itself fails (not findings, but tool errors)
    #[serde(default)]
    pub fail_on_error: bool,

    /// Minimum PMD priority to report (1=highest, 5=lowest)
    #[serde(default = "default_pmd_min_priority")]
    pub min_priority: u8,

    /// Additional PMD command-line arguments
    #[serde(default)]
    pub extra_args: Vec<String>,
}

impl Default for PmdProviderConfig {
    fn default() -> Self {
        Self {
            configured: false,
            java_path: default_java_path(),
            pmd_path: String::new(),
            rulesets: default_pmd_rulesets(),
            timeout_ms: default_pmd_timeout(),
            include_patterns: default_pmd_include_patterns(),
            exclude_patterns: default_pmd_exclude_patterns(),
            severity_map: default_pmd_severity_map(),
            fail_on_error: false,
            min_priority: default_pmd_min_priority(),
            extra_args: Vec::new(),
        }
    }
}

fn default_java_path() -> String {
    "java".to_string()
}

fn default_pmd_rulesets() -> Vec<String> {
    vec![
        "category/java/security.xml".to_string(),
        "category/java/bestpractices.xml".to_string(),
        "category/java/errorprone.xml".to_string(),
    ]
}

fn default_pmd_timeout() -> u64 {
    600_000 // 10 minutes
}

fn default_pmd_include_patterns() -> Vec<String> {
    vec!["**/*.java".to_string()]
}

fn default_pmd_exclude_patterns() -> Vec<String> {
    vec![
        "**/target/**".to_string(),
        "**/build/**".to_string(),
        "**/generated/**".to_string(),
        "**/out/**".to_string(),
        "**/.git/**".to_string(),
        "**/node_modules/**".to_string(),
    ]
}

fn default_pmd_severity_map() -> HashMap<String, Severity> {
    let mut map = HashMap::new();
    map.insert("1".to_string(), Severity::Critical);
    map.insert("2".to_string(), Severity::Error);
    map.insert("3".to_string(), Severity::Warning);
    map.insert("4".to_string(), Severity::Info);
    map.insert("5".to_string(), Severity::Info);
    map
}

fn default_pmd_min_priority() -> u8 {
    5 // Report all priorities by default
}

/// Oxlint provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OxlintProviderConfig {
    /// Whether Oxlint provider is configured
    #[serde(default)]
    pub configured: bool,

    /// Path to oxlint binary (default: search PATH)
    #[serde(default)]
    pub binary_path: String,

    /// Timeout for oxlint execution in milliseconds
    #[serde(default = "default_oxlint_timeout")]
    pub timeout_ms: u64,

    /// Additional oxlint command-line arguments
    #[serde(default)]
    pub extra_args: Vec<String>,
}

impl Default for OxlintProviderConfig {
    fn default() -> Self {
        Self {
            configured: false,
            binary_path: String::new(),
            timeout_ms: default_oxlint_timeout(),
            extra_args: Vec::new(),
        }
    }
}

fn default_oxlint_timeout() -> u64 {
    300_000 // 5 minutes
}

/// Gosec provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GosecProviderConfig {
    /// Whether Gosec provider is configured
    #[serde(default)]
    pub configured: bool,

    /// Path to gosec binary (default: search PATH)
    #[serde(default)]
    pub binary_path: String,

    /// Timeout for gosec execution in milliseconds
    #[serde(default = "default_gosec_timeout")]
    pub timeout_ms: u64,

    /// Gosec rules to exclude (e.g., ["G104", "G304"])
    #[serde(default)]
    pub exclude_rules: Vec<String>,

    /// Gosec rules to include only (if set, only these rules run)
    #[serde(default)]
    pub include_rules: Vec<String>,

    /// Additional gosec command-line arguments
    #[serde(default)]
    pub extra_args: Vec<String>,
}

impl Default for GosecProviderConfig {
    fn default() -> Self {
        Self {
            configured: false,
            binary_path: String::new(),
            timeout_ms: default_gosec_timeout(),
            exclude_rules: Vec::new(),
            include_rules: Vec::new(),
            extra_args: Vec::new(),
        }
    }
}

fn default_gosec_timeout() -> u64 {
    300_000 // 5 minutes
}

/// Native Oxc provider configuration (Rust-native JS/TS linting)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OxcProviderConfig {
    /// Whether Oxc provider is configured
    #[serde(default)]
    pub configured: bool,

    /// Rules to enable (empty = all rules)
    #[serde(default)]
    pub enable_rules: Vec<String>,

    /// Rules to disable
    #[serde(default)]
    pub disable_rules: Vec<String>,

    /// Severity overrides per rule ID (e.g., "js/oxc/no-debugger" -> "info")
    #[serde(default)]
    pub severity_overrides: HashMap<String, Severity>,
}

/// OSV ecosystem identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsvEcosystem {
    /// crates.io (Rust)
    #[serde(rename = "crates.io")]
    CratesIo,
    /// npm (JavaScript/TypeScript)
    Npm,
    /// PyPI (Python)
    PyPI,
    /// Go modules
    Go,
    /// Maven (Java)
    Maven,
}

impl std::fmt::Display for OsvEcosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsvEcosystem::CratesIo => write!(f, "crates.io"),
            OsvEcosystem::Npm => write!(f, "npm"),
            OsvEcosystem::PyPI => write!(f, "PyPI"),
            OsvEcosystem::Go => write!(f, "Go"),
            OsvEcosystem::Maven => write!(f, "Maven"),
        }
    }
}

/// OSV provider configuration (multi-language dependency vulnerability scanning)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvProviderConfig {
    /// Whether OSV provider is configured
    #[serde(default)]
    pub configured: bool,

    /// Include dev dependencies in scan (default: false)
    #[serde(default)]
    pub include_dev_deps: bool,

    /// Cache TTL as duration string (default: "24h")
    /// Supported formats: "1h", "30m", "24h", "7d"
    #[serde(default = "default_osv_cache_ttl")]
    pub cache_ttl: String,

    /// Enabled ecosystems (default: all)
    #[serde(default = "default_osv_ecosystems")]
    pub enabled_ecosystems: Vec<OsvEcosystem>,

    /// Severity overrides by OSV ID or CVE ID
    /// e.g., "GHSA-xxx" -> "warning", "CVE-2024-xxx" -> "info"
    #[serde(default)]
    pub severity_overrides: HashMap<String, Severity>,

    /// Allowlist/ignore list by OSV ID or CVE ID
    /// Vulnerabilities in this list will not be reported
    #[serde(default)]
    pub ignore_list: Vec<String>,

    /// Offline mode - use cache only, no network requests
    #[serde(default)]
    pub offline: bool,

    /// Custom cache directory (default: .rma/cache)
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
}

impl Default for OsvProviderConfig {
    fn default() -> Self {
        Self {
            configured: false,
            include_dev_deps: false,
            cache_ttl: default_osv_cache_ttl(),
            enabled_ecosystems: default_osv_ecosystems(),
            severity_overrides: HashMap::new(),
            ignore_list: Vec::new(),
            offline: false,
            cache_dir: None,
        }
    }
}

fn default_osv_cache_ttl() -> String {
    "24h".to_string()
}

fn default_osv_ecosystems() -> Vec<OsvEcosystem> {
    vec![
        OsvEcosystem::CratesIo,
        OsvEcosystem::Npm,
        OsvEcosystem::PyPI,
        OsvEcosystem::Go,
        OsvEcosystem::Maven,
    ]
}

/// Baseline configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BaselineConfig {
    /// Path to baseline file
    #[serde(default = "default_baseline_file")]
    pub file: PathBuf,

    /// Baseline mode
    #[serde(default)]
    pub mode: BaselineMode,
}

fn default_baseline_file() -> PathBuf {
    PathBuf::from(".rma/baseline.json")
}

// =============================================================================
// SUPPRESSION DATABASE CONFIGURATION
// =============================================================================

/// Configuration for the suppression database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionConfig {
    /// Path to the suppression database (relative to project root)
    #[serde(default = "default_suppression_database")]
    pub database: PathBuf,

    /// Default expiration period for new suppressions (e.g., "90d", "30d", "7d")
    #[serde(default = "default_expiration")]
    pub default_expiration: String,

    /// Whether a ticket reference is required for new suppressions
    #[serde(default)]
    pub require_ticket: bool,

    /// Maximum expiration period allowed (e.g., "365d")
    #[serde(default = "default_max_expiration")]
    pub max_expiration: String,

    /// Whether to enable the database suppression source
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

impl Default for SuppressionConfig {
    fn default() -> Self {
        Self {
            database: default_suppression_database(),
            default_expiration: default_expiration(),
            require_ticket: false,
            max_expiration: default_max_expiration(),
            enabled: true,
        }
    }
}

fn default_suppression_database() -> PathBuf {
    PathBuf::from(".rma/suppressions.db")
}

fn default_expiration() -> String {
    "90d".to_string()
}

fn default_max_expiration() -> String {
    "365d".to_string()
}

fn default_enabled() -> bool {
    true
}

/// Parse a duration string (e.g., "90d", "30d", "7d") to days
pub fn parse_expiration_days(s: &str) -> Option<u32> {
    let s = s.trim().to_lowercase();
    if let Some(days_str) = s.strip_suffix('d') {
        days_str.parse().ok()
    } else if let Some(weeks_str) = s.strip_suffix('w') {
        weeks_str.parse::<u32>().ok().map(|w| w * 7)
    } else if let Some(months_str) = s.strip_suffix('m') {
        months_str.parse::<u32>().ok().map(|m| m * 30)
    } else {
        // Try parsing as plain number (days)
        s.parse().ok()
    }
}

/// Current supported config version
pub const CURRENT_CONFIG_VERSION: u32 = 1;

/// Complete RMA TOML configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RmaTomlConfig {
    /// Config format version (for future compatibility)
    #[serde(default)]
    pub config_version: Option<u32>,

    /// Scan path configuration
    #[serde(default)]
    pub scan: ScanConfig,

    /// Rules configuration
    #[serde(default)]
    pub rules: RulesConfig,

    /// Rulesets configuration (named groups of rules)
    #[serde(default)]
    pub rulesets: RulesetsConfig,

    /// Profiles configuration
    #[serde(default)]
    pub profiles: ProfilesConfig,

    /// Severity overrides by rule ID
    #[serde(default)]
    pub severity: HashMap<String, Severity>,

    /// Path-specific threshold overrides
    #[serde(default)]
    pub threshold_overrides: Vec<ThresholdOverride>,

    /// Allowlist configuration
    #[serde(default)]
    pub allow: AllowConfig,

    /// Baseline configuration
    #[serde(default)]
    pub baseline: BaselineConfig,

    /// Analysis providers configuration
    #[serde(default)]
    pub providers: ProvidersConfig,

    /// Suppression database configuration
    #[serde(default)]
    pub suppressions: SuppressionConfig,
}

/// Result of loading a config file
#[derive(Debug)]
pub struct ConfigLoadResult {
    /// The loaded configuration
    pub config: RmaTomlConfig,
    /// Warning if version was missing
    pub version_warning: Option<String>,
}

impl RmaTomlConfig {
    /// Load configuration from file with version validation
    pub fn load(path: &Path) -> Result<Self, String> {
        let result = Self::load_with_validation(path)?;
        Ok(result.config)
    }

    /// Load configuration from file with full validation info
    pub fn load_with_validation(path: &Path) -> Result<ConfigLoadResult, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        let config: RmaTomlConfig =
            toml::from_str(&content).map_err(|e| format!("Failed to parse TOML: {}", e))?;

        // Validate version
        let version_warning = config.validate_version()?;

        Ok(ConfigLoadResult {
            config,
            version_warning,
        })
    }

    /// Validate config version, returns warning message if version is missing
    fn validate_version(&self) -> Result<Option<String>, String> {
        match self.config_version {
            Some(CURRENT_CONFIG_VERSION) => Ok(None),
            Some(version) if version > CURRENT_CONFIG_VERSION => Err(format!(
                "Unsupported config version: {}. Maximum supported version is {}. \
                     Please upgrade RMA or use a compatible config format.",
                version, CURRENT_CONFIG_VERSION
            )),
            Some(version) => {
                // Version 0 or any future "older than current" version
                Err(format!(
                    "Invalid config version: {}. Expected version {}.",
                    version, CURRENT_CONFIG_VERSION
                ))
            }
            None => Ok(Some(
                "Config file is missing 'config_version'. Assuming version 1. \
                 Add 'config_version = 1' to suppress this warning."
                    .to_string(),
            )),
        }
    }

    /// Check if config version is present
    pub fn has_version(&self) -> bool {
        self.config_version.is_some()
    }

    /// Get the effective config version (defaults to 1 if missing)
    pub fn effective_version(&self) -> u32 {
        self.config_version.unwrap_or(CURRENT_CONFIG_VERSION)
    }

    /// Find and load configuration from standard locations
    pub fn discover(start_path: &Path) -> Option<(PathBuf, Self)> {
        let candidates = [
            start_path.join("rma.toml"),
            start_path.join(".rma/rma.toml"),
            start_path.join(".rma.toml"),
        ];

        for candidate in &candidates {
            if candidate.exists()
                && let Ok(config) = Self::load(candidate)
            {
                return Some((candidate.clone(), config));
            }
        }

        // Check parent directories up to 5 levels
        let mut current = start_path.to_path_buf();
        for _ in 0..5 {
            if let Some(parent) = current.parent() {
                let config_path = parent.join("rma.toml");
                if config_path.exists()
                    && let Ok(config) = Self::load(&config_path)
                {
                    return Some((config_path, config));
                }
                current = parent.to_path_buf();
            } else {
                break;
            }
        }

        None
    }

    /// Validate configuration for errors and conflicts
    pub fn validate(&self) -> Vec<ConfigWarning> {
        let mut warnings = Vec::new();

        // Check config version
        if self.config_version.is_none() {
            warnings.push(ConfigWarning {
                level: WarningLevel::Warning,
                message: "Missing 'config_version'. Add 'config_version = 1' to your config file."
                    .to_string(),
            });
        } else if let Some(version) = self.config_version
            && version > CURRENT_CONFIG_VERSION
        {
            warnings.push(ConfigWarning {
                level: WarningLevel::Error,
                message: format!(
                    "Unsupported config version: {}. Maximum supported is {}.",
                    version, CURRENT_CONFIG_VERSION
                ),
            });
        }

        // Check for conflicting enable/disable rules
        for disabled in &self.rules.disable {
            for enabled in &self.rules.enable {
                if enabled == disabled {
                    warnings.push(ConfigWarning {
                        level: WarningLevel::Warning,
                        message: format!(
                            "Rule '{}' is both enabled and disabled (disable takes precedence)",
                            disabled
                        ),
                    });
                }
            }
        }

        // Check threshold overrides have valid patterns
        for (i, override_) in self.threshold_overrides.iter().enumerate() {
            if override_.path.is_empty() {
                warnings.push(ConfigWarning {
                    level: WarningLevel::Error,
                    message: format!("threshold_overrides[{}]: path cannot be empty", i),
                });
            }
        }

        // Check baseline file path
        if self.baseline.mode == BaselineMode::NewOnly && !self.baseline.file.exists() {
            warnings.push(ConfigWarning {
                level: WarningLevel::Warning,
                message: format!(
                    "Baseline mode is 'new-only' but baseline file '{}' does not exist. Run 'rma baseline' first.",
                    self.baseline.file.display()
                ),
            });
        }

        // Check severity overrides reference valid severities
        for rule_id in self.severity.keys() {
            if rule_id.is_empty() {
                warnings.push(ConfigWarning {
                    level: WarningLevel::Error,
                    message: "Empty rule ID in severity overrides".to_string(),
                });
            }
        }

        // Validate provider configuration
        if self.providers.enabled.contains(&ProviderType::Pmd) {
            // PMD is enabled - check if it's configured
            if !self.providers.pmd.configured && self.providers.pmd.pmd_path.is_empty() {
                warnings.push(ConfigWarning {
                    level: WarningLevel::Warning,
                    message: "PMD provider is enabled but not configured. Set [providers.pmd] configured = true or provide pmd_path.".to_string(),
                });
            }

            // Check PMD rulesets
            if self.providers.pmd.rulesets.is_empty() {
                warnings.push(ConfigWarning {
                    level: WarningLevel::Warning,
                    message:
                        "PMD provider has no rulesets configured. Add rulesets to [providers.pmd]."
                            .to_string(),
                });
            }

            // Check severity map validity
            for priority in self.providers.pmd.severity_map.keys() {
                if !["1", "2", "3", "4", "5"].contains(&priority.as_str()) {
                    warnings.push(ConfigWarning {
                        level: WarningLevel::Warning,
                        message: format!(
                            "Invalid PMD priority '{}' in severity_map. Valid priorities: 1-5.",
                            priority
                        ),
                    });
                }
            }
        }

        if self.providers.enabled.contains(&ProviderType::Oxlint)
            && !self.providers.oxlint.configured
        {
            warnings.push(ConfigWarning {
                level: WarningLevel::Warning,
                message: "Oxlint provider is enabled but not configured. Set [providers.oxlint] configured = true.".to_string(),
            });
        }

        warnings
    }

    /// Check if a specific provider is enabled
    pub fn is_provider_enabled(&self, provider: ProviderType) -> bool {
        self.providers.enabled.contains(&provider)
    }

    /// Get the list of enabled providers
    pub fn get_enabled_providers(&self) -> &[ProviderType] {
        &self.providers.enabled
    }

    /// Get PMD provider config (if PMD is enabled)
    pub fn get_pmd_config(&self) -> Option<&PmdProviderConfig> {
        if self.is_provider_enabled(ProviderType::Pmd) {
            Some(&self.providers.pmd)
        } else {
            None
        }
    }

    /// Check if a rule is enabled (without ruleset filtering)
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        self.is_rule_enabled_with_ruleset(rule_id, None)
    }

    /// Check if a rule is enabled with optional ruleset filter
    ///
    /// If a ruleset is specified, only rules in that ruleset are considered enabled.
    /// Explicit disable always takes precedence.
    pub fn is_rule_enabled_with_ruleset(&self, rule_id: &str, ruleset: Option<&str>) -> bool {
        // Check if explicitly disabled - always takes precedence
        for pattern in &self.rules.disable {
            if Self::matches_pattern(rule_id, pattern) {
                return false;
            }
        }

        // If a ruleset is specified, check if rule is in that ruleset
        if let Some(ruleset_name) = ruleset {
            let ruleset_rules = self.get_ruleset_rules(ruleset_name);
            if !ruleset_rules.is_empty() {
                // Rule must be in the ruleset to be enabled
                return ruleset_rules
                    .iter()
                    .any(|r| Self::matches_pattern(rule_id, r));
            }
        }

        // Check if explicitly enabled
        for pattern in &self.rules.enable {
            if Self::matches_pattern(rule_id, pattern) {
                return true;
            }
        }

        false
    }

    /// Get rules for a named ruleset
    pub fn get_ruleset_rules(&self, name: &str) -> Vec<String> {
        match name {
            "security" => self.rulesets.security.clone(),
            "maintainability" => self.rulesets.maintainability.clone(),
            _ => self.rulesets.custom.get(name).cloned().unwrap_or_default(),
        }
    }

    /// Get all available ruleset names
    pub fn get_ruleset_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if !self.rulesets.security.is_empty() {
            names.push("security".to_string());
        }
        if !self.rulesets.maintainability.is_empty() {
            names.push("maintainability".to_string());
        }
        names.extend(self.rulesets.custom.keys().cloned());
        names
    }

    /// Get severity override for a rule
    pub fn get_severity_override(&self, rule_id: &str) -> Option<Severity> {
        self.severity.get(rule_id).copied()
    }

    /// Get thresholds for a path, applying overrides
    pub fn get_thresholds_for_path(&self, path: &Path, profile: Profile) -> ProfileThresholds {
        let mut thresholds = self.profiles.get_thresholds(profile).clone();

        // Apply path-specific overrides
        let path_str = path.to_string_lossy();
        for override_ in &self.threshold_overrides {
            if Self::matches_glob(&path_str, &override_.path) {
                if let Some(v) = override_.max_function_lines {
                    thresholds.max_function_lines = v;
                }
                if let Some(v) = override_.max_complexity {
                    thresholds.max_complexity = v;
                }
                if let Some(v) = override_.max_cognitive_complexity {
                    thresholds.max_cognitive_complexity = v;
                }
            }
        }

        thresholds
    }

    /// Check if a path is allowed for a specific rule
    pub fn is_path_allowed(&self, path: &Path, rule_type: AllowType) -> bool {
        let path_str = path.to_string_lossy();
        let allowed_paths = match rule_type {
            AllowType::InnerHtml => &self.allow.innerhtml_paths,
            AllowType::Eval => &self.allow.eval_paths,
            AllowType::UnsafeRust => &self.allow.unsafe_rust_paths,
        };

        for pattern in allowed_paths {
            if Self::matches_glob(&path_str, pattern) {
                return true;
            }
        }

        false
    }

    fn matches_pattern(rule_id: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if let Some(prefix) = pattern.strip_suffix("/*") {
            return rule_id.starts_with(prefix);
        }

        rule_id == pattern
    }

    fn matches_glob(path: &str, pattern: &str) -> bool {
        // Simple glob matching (supports * and **)
        let pattern = pattern
            .replace("**", "§")
            .replace('*', "[^/]*")
            .replace('§', ".*");
        regex::Regex::new(&format!("^{}$", pattern))
            .map(|re| re.is_match(path))
            .unwrap_or(false)
    }

    /// Generate default configuration as TOML string
    pub fn default_toml(profile: Profile) -> String {
        let thresholds = ProfileThresholds::for_profile(profile);

        format!(
            r#"# RMA Configuration
# Documentation: https://github.com/bumahkib7/rust-monorepo-analyzer

# Config format version (required for future compatibility)
config_version = 1

[scan]
# Paths to include in scanning (default: all supported files)
include = ["src/**", "lib/**", "scripts/**"]

# Paths to exclude from scanning
exclude = [
    "node_modules/**",
    "target/**",
    "dist/**",
    "build/**",
    "vendor/**",
    "**/*.min.js",
    "**/*.bundle.js",
]

# Maximum file size to scan (10MB default)
max_file_size = 10485760

[rules]
# Rules to enable (wildcards supported)
enable = ["*"]

# Rules to disable (takes precedence over enable)
disable = []

# Global ignore paths - findings in these paths are suppressed for all rules
# Supports glob patterns. Uncomment to customize.
# ignore_paths = ["**/vendor/**", "**/generated/**"]

# Per-rule ignore paths - suppress specific rules in specific paths
# Note: Security rules (command-injection, hardcoded-secret, etc.) cannot be
# suppressed via path ignores, only via inline comments with reason.
# [rules.ignore_paths_by_rule]
# "generic/long-function" = ["**/tests/**", "**/examples/**"]
# "js/console-log" = ["**/debug/**"]

# Default test/example suppressions are automatically applied in --mode pr/ci
# This reduces noise from test files. Security rules are NOT suppressed.

[profiles]
# Default profile: fast, balanced, or strict
default = "{profile}"

[profiles.fast]
max_function_lines = 200
max_complexity = 25
max_cognitive_complexity = 35
max_file_lines = 2000

[profiles.balanced]
max_function_lines = {max_function_lines}
max_complexity = {max_complexity}
max_cognitive_complexity = {max_cognitive_complexity}
max_file_lines = 1000

[profiles.strict]
max_function_lines = 50
max_complexity = 10
max_cognitive_complexity = 15
max_file_lines = 500

[rulesets]
# Named rule groups for targeted scanning
security = ["js/innerhtml-xss", "js/timer-string-eval", "js/dynamic-code-execution", "rust/unsafe-block", "python/shell-injection"]
maintainability = ["generic/long-function", "generic/high-complexity", "js/console-log"]

[severity]
# Override severity for specific rules
# "generic/long-function" = "warning"
# "js/innerhtml-xss" = "error"
# "rust/unsafe-block" = "warning"

# [[threshold_overrides]]
# path = "src/legacy/**"
# max_function_lines = 300
# max_complexity = 30

# [[threshold_overrides]]
# path = "tests/**"
# disable_rules = ["generic/long-function"]

[allow]
# Approved patterns that won't trigger alerts
settimeout_string = false
settimeout_function = true
innerhtml_paths = []
eval_paths = []
unsafe_rust_paths = []
approved_secrets = []

[baseline]
# Baseline file for tracking legacy issues
file = ".rma/baseline.json"
# Mode: "all" or "new-only"
mode = "all"

# =============================================================================
# ANALYSIS PROVIDERS
# =============================================================================
# RMA supports external analysis providers for extended language coverage.
# Providers can be enabled/disabled individually.

[providers]
# List of enabled providers
# Default: ["rma", "oxc"] - built-in rules + native JS/TS linting
enabled = ["rma", "oxc"]
# To add PMD for Java: enabled = ["rma", "oxc", "pmd"]
# To add external Oxlint: enabled = ["rma", "oxc", "oxlint"]

# -----------------------------------------------------------------------------
# PMD Provider - Java Static Analysis (optional)
# -----------------------------------------------------------------------------
# PMD provides comprehensive Java security and quality analysis.
# Requires: Java runtime and PMD installation
#
# [providers.pmd]
# configured = true
# java_path = "java"                    # Path to java binary
# pmd_path = ""                         # Path to pmd binary (or leave empty to use PATH)
# rulesets = [
#     "category/java/security.xml",
#     "category/java/bestpractices.xml",
#     "category/java/errorprone.xml",
# ]
# timeout_ms = 600000                   # 10 minutes timeout
# include_patterns = ["**/*.java"]
# exclude_patterns = ["**/target/**", "**/build/**", "**/generated/**"]
# fail_on_error = false                 # Continue scan if PMD fails
# min_priority = 5                      # Report all priorities (1-5)
# extra_args = []                       # Additional PMD CLI arguments

# [providers.pmd.severity_map]
# # Map PMD priority (1-5) to RMA severity
# "1" = "critical"
# "2" = "error"
# "3" = "warning"
# "4" = "info"
# "5" = "info"

# -----------------------------------------------------------------------------
# Oxlint Provider - Fast JavaScript/TypeScript Linting (optional)
# -----------------------------------------------------------------------------
# [providers.oxlint]
# configured = true
# binary_path = ""                      # Path to oxlint binary (or leave empty to use PATH)
# timeout_ms = 300000                   # 5 minutes timeout
# extra_args = []
"#,
            profile = profile,
            max_function_lines = thresholds.max_function_lines,
            max_complexity = thresholds.max_complexity,
            max_cognitive_complexity = thresholds.max_cognitive_complexity,
        )
    }
}

/// Type of allowlist check
#[derive(Debug, Clone, Copy)]
pub enum AllowType {
    InnerHtml,
    Eval,
    UnsafeRust,
}

/// Source of a configuration value (for precedence tracking)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigSource {
    /// Built-in default value
    Default,
    /// From rma.toml configuration file
    ConfigFile,
    /// From CLI flag or environment variable
    CliFlag,
}

impl std::fmt::Display for ConfigSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigSource::Default => write!(f, "default"),
            ConfigSource::ConfigFile => write!(f, "config-file"),
            ConfigSource::CliFlag => write!(f, "cli-flag"),
        }
    }
}

/// Effective (resolved) configuration after applying precedence
///
/// Precedence order (highest to lowest):
/// 1. CLI flags (--config, --profile, --baseline-mode)
/// 2. rma.toml in repo root (or explicit --config path)
/// 3. Built-in defaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveConfig {
    /// Source of the configuration file (if any)
    pub config_file: Option<PathBuf>,

    /// Active profile
    pub profile: Profile,

    /// Where the profile came from
    pub profile_source: ConfigSource,

    /// Resolved thresholds
    pub thresholds: ProfileThresholds,

    /// Number of enabled rules
    pub enabled_rules_count: usize,

    /// Number of disabled rules
    pub disabled_rules_count: usize,

    /// Number of severity overrides
    pub severity_overrides_count: usize,

    /// Threshold overrides (paths in order)
    pub threshold_override_paths: Vec<String>,

    /// Baseline mode
    pub baseline_mode: BaselineMode,

    /// Where baseline mode came from
    pub baseline_mode_source: ConfigSource,

    /// Exclude patterns
    pub exclude_patterns: Vec<String>,

    /// Include patterns
    pub include_patterns: Vec<String>,
}

impl EffectiveConfig {
    /// Build effective config from sources with proper precedence
    pub fn resolve(
        toml_config: Option<&RmaTomlConfig>,
        config_path: Option<&Path>,
        cli_profile: Option<Profile>,
        cli_baseline_mode: bool,
    ) -> Self {
        // Resolve profile: CLI > config > default
        let (profile, profile_source) = if let Some(p) = cli_profile {
            (p, ConfigSource::CliFlag)
        } else if let Some(cfg) = toml_config {
            (cfg.profiles.default, ConfigSource::ConfigFile)
        } else {
            (Profile::default(), ConfigSource::Default)
        };

        // Resolve baseline mode: CLI > config > default
        let (baseline_mode, baseline_mode_source) = if cli_baseline_mode {
            (BaselineMode::NewOnly, ConfigSource::CliFlag)
        } else if let Some(cfg) = toml_config {
            (cfg.baseline.mode, ConfigSource::ConfigFile)
        } else {
            (BaselineMode::default(), ConfigSource::Default)
        };

        // Get thresholds for profile
        let thresholds = toml_config
            .map(|cfg| cfg.profiles.get_thresholds(profile).clone())
            .unwrap_or_else(|| ProfileThresholds::for_profile(profile));

        // Count rules
        let (enabled_rules_count, disabled_rules_count) = toml_config
            .map(|cfg| (cfg.rules.enable.len(), cfg.rules.disable.len()))
            .unwrap_or((1, 0)); // default: enable = ["*"]

        // Severity overrides
        let severity_overrides_count = toml_config.map(|cfg| cfg.severity.len()).unwrap_or(0);

        // Threshold override paths
        let threshold_override_paths = toml_config
            .map(|cfg| {
                cfg.threshold_overrides
                    .iter()
                    .map(|o| o.path.clone())
                    .collect()
            })
            .unwrap_or_default();

        // Patterns
        let exclude_patterns = toml_config
            .map(|cfg| cfg.scan.exclude.clone())
            .unwrap_or_default();

        let include_patterns = toml_config
            .map(|cfg| cfg.scan.include.clone())
            .unwrap_or_default();

        Self {
            config_file: config_path.map(|p| p.to_path_buf()),
            profile,
            profile_source,
            thresholds,
            enabled_rules_count,
            disabled_rules_count,
            severity_overrides_count,
            threshold_override_paths,
            baseline_mode,
            baseline_mode_source,
            exclude_patterns,
            include_patterns,
        }
    }

    /// Format as human-readable text
    pub fn to_text(&self) -> String {
        let mut out = String::new();

        out.push_str("Effective Configuration\n");
        out.push_str("═══════════════════════════════════════════════════════════\n\n");

        // Config file
        out.push_str("  Config file:        ");
        match &self.config_file {
            Some(p) => out.push_str(&format!("{}\n", p.display())),
            None => out.push_str("(none - using defaults)\n"),
        }

        // Profile
        out.push_str(&format!(
            "  Profile:            {} (from {})\n",
            self.profile, self.profile_source
        ));

        // Thresholds
        out.push_str("\n  Thresholds:\n");
        out.push_str(&format!(
            "    max_function_lines:     {}\n",
            self.thresholds.max_function_lines
        ));
        out.push_str(&format!(
            "    max_complexity:         {}\n",
            self.thresholds.max_complexity
        ));
        out.push_str(&format!(
            "    max_cognitive_complexity: {}\n",
            self.thresholds.max_cognitive_complexity
        ));
        out.push_str(&format!(
            "    max_file_lines:         {}\n",
            self.thresholds.max_file_lines
        ));

        // Rules
        out.push_str("\n  Rules:\n");
        out.push_str(&format!(
            "    enabled patterns:       {}\n",
            self.enabled_rules_count
        ));
        out.push_str(&format!(
            "    disabled patterns:      {}\n",
            self.disabled_rules_count
        ));
        out.push_str(&format!(
            "    severity overrides:     {}\n",
            self.severity_overrides_count
        ));

        // Threshold overrides
        if !self.threshold_override_paths.is_empty() {
            out.push_str("\n  Threshold overrides:\n");
            for path in &self.threshold_override_paths {
                out.push_str(&format!("    - {}\n", path));
            }
        }

        // Baseline
        out.push_str(&format!(
            "\n  Baseline mode:      {:?} (from {})\n",
            self.baseline_mode, self.baseline_mode_source
        ));

        out
    }

    /// Format as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Configuration warning or error
#[derive(Debug, Clone)]
pub struct ConfigWarning {
    pub level: WarningLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningLevel {
    Warning,
    Error,
}

/// Inline suppression comment parsed from source code
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineSuppression {
    /// The rule ID to suppress
    pub rule_id: String,
    /// The reason for suppression (required in strict profile)
    pub reason: Option<String>,
    /// Line number where the suppression comment appears
    pub line: usize,
    /// Type of suppression
    pub suppression_type: SuppressionType,
}

/// Type of inline suppression
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuppressionType {
    /// Suppresses the next line only
    NextLine,
    /// Suppresses until end of block/function (or file-level until blank line)
    Block,
}

impl InlineSuppression {
    /// Parse a suppression comment from a line of code
    ///
    /// Supported formats:
    /// - `// rma-ignore-next-line <rule_id> reason="<text>"`
    /// - `// rma-ignore <rule_id> reason="<text>"`
    /// - `# rma-ignore-next-line <rule_id> reason="<text>"` (Python)
    pub fn parse(line: &str, line_number: usize) -> Option<Self> {
        let trimmed = line.trim();

        // Check for comment prefixes
        let comment_body = if let Some(rest) = trimmed.strip_prefix("//") {
            rest.trim()
        } else if let Some(rest) = trimmed.strip_prefix('#') {
            rest.trim()
        } else {
            return None;
        };

        // Check for rma-ignore-next-line
        if let Some(rest) = comment_body.strip_prefix("rma-ignore-next-line") {
            return Self::parse_suppression_body(
                rest.trim(),
                line_number,
                SuppressionType::NextLine,
            );
        }

        // Check for rma-ignore (block level)
        if let Some(rest) = comment_body.strip_prefix("rma-ignore") {
            return Self::parse_suppression_body(rest.trim(), line_number, SuppressionType::Block);
        }

        None
    }

    fn parse_suppression_body(
        body: &str,
        line_number: usize,
        suppression_type: SuppressionType,
    ) -> Option<Self> {
        if body.is_empty() {
            return None;
        }

        // Parse: <rule_id> [reason="<text>"]
        let mut parts = body.splitn(2, ' ');
        let rule_id = parts.next()?.trim().to_string();

        if rule_id.is_empty() {
            return None;
        }

        let reason = parts.next().and_then(|rest| {
            // Look for reason="..."
            if let Some(start) = rest.find("reason=\"") {
                let after_quote = &rest[start + 8..];
                if let Some(end) = after_quote.find('"') {
                    return Some(after_quote[..end].to_string());
                }
            }
            None
        });

        Some(Self {
            rule_id,
            reason,
            line: line_number,
            suppression_type,
        })
    }

    /// Check if this suppression applies to a finding at the given line
    pub fn applies_to(&self, finding_line: usize, rule_id: &str) -> bool {
        if self.rule_id != rule_id && self.rule_id != "*" {
            return false;
        }

        match self.suppression_type {
            SuppressionType::NextLine => finding_line == self.line + 1,
            SuppressionType::Block => finding_line >= self.line,
        }
    }

    /// Validate suppression (check if reason is required and present)
    pub fn validate(&self, require_reason: bool) -> Result<(), String> {
        if require_reason && self.reason.is_none() {
            return Err(format!(
                "Suppression for '{}' at line {} requires a reason in strict profile",
                self.rule_id, self.line
            ));
        }
        Ok(())
    }
}

/// Parse all inline suppressions from source code
pub fn parse_inline_suppressions(content: &str) -> Vec<InlineSuppression> {
    content
        .lines()
        .enumerate()
        .filter_map(|(i, line)| InlineSuppression::parse(line, i + 1))
        .collect()
}

/// Stable fingerprint for a finding
///
/// Fingerprints are designed to survive:
/// - Line number changes (refactoring moves code)
/// - Minor whitespace changes
/// - Non-semantic message text changes
///
/// Fingerprint inputs (in order):
/// 1. rule_id (e.g., "js/innerhtml-xss")
/// 2. file path (normalized, unix separators)
/// 3. normalized snippet (trimmed, collapsed whitespace)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Generate a stable fingerprint for a finding
    pub fn generate(rule_id: &str, file_path: &Path, snippet: &str) -> Self {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // 1. Rule ID
        hasher.update(rule_id.as_bytes());
        hasher.update(b"|");

        // 2. Normalized file path (unix separators, lowercase for case-insensitive FS)
        let normalized_path = file_path
            .to_string_lossy()
            .replace('\\', "/")
            .to_lowercase();
        hasher.update(normalized_path.as_bytes());
        hasher.update(b"|");

        // 3. Normalized snippet (collapse whitespace, trim)
        let normalized_snippet = Self::normalize_snippet(snippet);
        hasher.update(normalized_snippet.as_bytes());

        let hash = hasher.finalize();
        Self(format!("sha256:{:x}", hash))
    }

    /// Normalize snippet for stable fingerprinting
    fn normalize_snippet(snippet: &str) -> String {
        snippet
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_string()
    }

    /// Get the fingerprint string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Create from existing fingerprint string
    pub fn from_string(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Fingerprint> for String {
    fn from(fp: Fingerprint) -> String {
        fp.0
    }
}

/// Baseline entry for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub rule_id: String,
    pub file: PathBuf,
    #[serde(default)]
    pub line: usize,
    pub fingerprint: String,
    pub first_seen: String,
    #[serde(default)]
    pub suppressed: bool,
    #[serde(default)]
    pub comment: Option<String>,
}

/// Baseline file containing known findings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Baseline {
    pub version: String,
    pub created: String,
    pub entries: Vec<BaselineEntry>,
}

impl Baseline {
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            created: chrono::Utc::now().to_rfc3339(),
            entries: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read baseline file: {}", e))?;

        serde_json::from_str(&content).map_err(|e| format!("Failed to parse baseline: {}", e))
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory: {}", e))?;
        }

        let content = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize baseline: {}", e))?;

        std::fs::write(path, content).map_err(|e| format!("Failed to write baseline: {}", e))
    }

    /// Check if a finding is in the baseline by fingerprint
    pub fn contains_fingerprint(&self, fingerprint: &Fingerprint) -> bool {
        self.entries
            .iter()
            .any(|e| e.fingerprint == fingerprint.as_str())
    }

    /// Check if a finding is in the baseline (legacy method)
    pub fn contains(&self, rule_id: &str, file: &Path, fingerprint: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.rule_id == rule_id && e.file == file && e.fingerprint == fingerprint)
    }

    /// Add a finding to the baseline using stable fingerprint
    pub fn add_with_fingerprint(
        &mut self,
        rule_id: String,
        file: PathBuf,
        line: usize,
        fingerprint: Fingerprint,
    ) {
        if !self.contains_fingerprint(&fingerprint) {
            self.entries.push(BaselineEntry {
                rule_id,
                file,
                line,
                fingerprint: fingerprint.into(),
                first_seen: chrono::Utc::now().to_rfc3339(),
                suppressed: false,
                comment: None,
            });
        }
    }

    /// Add a finding to the baseline (legacy method)
    pub fn add(&mut self, rule_id: String, file: PathBuf, line: usize, fingerprint: String) {
        if !self.contains(&rule_id, &file, &fingerprint) {
            self.entries.push(BaselineEntry {
                rule_id,
                file,
                line,
                fingerprint,
                first_seen: chrono::Utc::now().to_rfc3339(),
                suppressed: false,
                comment: None,
            });
        }
    }
}

// =============================================================================
// SUPPRESSION ENGINE
// =============================================================================

/// Result of checking if a finding should be suppressed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionResult {
    /// Whether the finding is suppressed
    pub suppressed: bool,
    /// Reason for suppression (if suppressed)
    pub reason: Option<String>,
    /// Source of suppression (path, inline, baseline, preset)
    pub source: Option<SuppressionSource>,
    /// Location of the suppression (e.g., line number for inline, glob pattern for path)
    pub location: Option<String>,
}

impl SuppressionResult {
    /// Create a not-suppressed result
    pub fn not_suppressed() -> Self {
        Self {
            suppressed: false,
            reason: None,
            source: None,
            location: None,
        }
    }

    /// Create a suppressed result
    pub fn suppressed(source: SuppressionSource, reason: String, location: String) -> Self {
        Self {
            suppressed: true,
            reason: Some(reason),
            source: Some(source),
            location: Some(location),
        }
    }
}

/// Source of a suppression
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuppressionSource {
    /// Suppressed by inline comment
    Inline,
    /// Suppressed by global ignore_paths config
    PathGlobal,
    /// Suppressed by per-rule ignore_paths_by_rule config
    PathRule,
    /// Suppressed by default test/example preset (--mode pr/ci)
    Preset,
    /// Suppressed by baseline
    Baseline,
    /// Suppressed by database entry
    Database,
}

impl std::fmt::Display for SuppressionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SuppressionSource::Inline => write!(f, "inline"),
            SuppressionSource::PathGlobal => write!(f, "path-global"),
            SuppressionSource::PathRule => write!(f, "path-rule"),
            SuppressionSource::Preset => write!(f, "preset"),
            SuppressionSource::Baseline => write!(f, "baseline"),
            SuppressionSource::Database => write!(f, "database"),
        }
    }
}

/// Engine for checking if findings should be suppressed
///
/// Consolidates all suppression logic:
/// - Global path ignores (rules.ignore_paths)
/// - Per-rule path ignores (rules.ignore_paths_by_rule)
/// - Inline suppressions (rma-ignore comments)
/// - Default test/example presets for PR/CI mode
/// - Baseline filtering
/// - Database suppressions (when enabled)
pub struct SuppressionEngine {
    /// Global ignore paths
    global_ignore_paths: Vec<String>,
    /// Per-rule ignore paths
    rule_ignore_paths: HashMap<String, Vec<String>>,
    /// Whether to apply default presets (for --mode pr/ci)
    use_default_presets: bool,
    /// Baseline for filtering existing findings
    baseline: Option<Baseline>,
    /// Compiled regex patterns for global ignores
    global_patterns: Vec<regex::Regex>,
    /// Compiled regex patterns for per-rule ignores
    rule_patterns: HashMap<String, Vec<regex::Regex>>,
    /// Compiled regex patterns for default test paths
    test_patterns: Vec<regex::Regex>,
    /// Compiled regex patterns for default example paths
    example_patterns: Vec<regex::Regex>,
    /// Optional suppression store for database-backed suppressions
    suppression_store: Option<std::sync::Arc<crate::suppression::SuppressionStore>>,
}

impl SuppressionEngine {
    /// Create a new suppression engine from config
    pub fn new(rules_config: &RulesConfig, use_default_presets: bool) -> Self {
        let global_patterns = rules_config
            .ignore_paths
            .iter()
            .filter_map(|p| Self::compile_glob(p))
            .collect();

        let mut rule_patterns = HashMap::new();
        for (rule_id, paths) in &rules_config.ignore_paths_by_rule {
            let patterns: Vec<regex::Regex> =
                paths.iter().filter_map(|p| Self::compile_glob(p)).collect();
            if !patterns.is_empty() {
                rule_patterns.insert(rule_id.clone(), patterns);
            }
        }

        let test_patterns = if use_default_presets {
            DEFAULT_TEST_IGNORE_PATHS
                .iter()
                .filter_map(|p| Self::compile_glob(p))
                .collect()
        } else {
            Vec::new()
        };

        let example_patterns = if use_default_presets {
            DEFAULT_EXAMPLE_IGNORE_PATHS
                .iter()
                .filter_map(|p| Self::compile_glob(p))
                .collect()
        } else {
            Vec::new()
        };

        Self {
            global_ignore_paths: rules_config.ignore_paths.clone(),
            rule_ignore_paths: rules_config.ignore_paths_by_rule.clone(),
            use_default_presets,
            baseline: None,
            global_patterns,
            rule_patterns,
            test_patterns,
            example_patterns,
            suppression_store: None,
        }
    }

    /// Create a suppression engine with just default presets (no config)
    pub fn with_defaults_only() -> Self {
        Self::new(&RulesConfig::default(), true)
    }

    /// Set the baseline for filtering
    pub fn with_baseline(mut self, baseline: Baseline) -> Self {
        self.baseline = Some(baseline);
        self
    }

    /// Set the suppression store for database-backed suppressions
    pub fn with_store(mut self, store: crate::suppression::SuppressionStore) -> Self {
        self.suppression_store = Some(std::sync::Arc::new(store));
        self
    }

    /// Set a shared suppression store reference
    pub fn with_store_ref(
        mut self,
        store: std::sync::Arc<crate::suppression::SuppressionStore>,
    ) -> Self {
        self.suppression_store = Some(store);
        self
    }

    /// Get a reference to the suppression store (if available)
    pub fn store(&self) -> Option<&crate::suppression::SuppressionStore> {
        self.suppression_store.as_ref().map(|s| s.as_ref())
    }

    /// Compile a glob pattern to a regex
    ///
    /// Handles cases like:
    /// - `**/tests/**` matches `src/tests/foo.rs` AND `tests/foo.rs`
    /// - `**/*.test.ts` matches `app.test.ts` AND `src/app.test.ts`
    fn compile_glob(pattern: &str) -> Option<regex::Regex> {
        let regex_pattern = pattern
            .replace('.', r"\.")
            .replace("**", "§")
            .replace('*', "[^/]*")
            .replace('§', ".*");

        // Handle patterns that start with .*/ to also match paths that start
        // directly with the pattern (e.g., "tests/foo.rs" matching "**/tests/**")
        let regex_pattern = if let Some(rest) = regex_pattern.strip_prefix(".*/") {
            // Make the leading .*/ optional: (^|.*/) matches start or .*/
            format!("(^|.*/){}", rest)
        } else if regex_pattern.starts_with(".*") {
            // Pattern starts with ** but no trailing slash, just use as-is
            regex_pattern
        } else {
            // Pattern doesn't start with **, anchor to start
            format!("^{}", regex_pattern)
        };

        regex::Regex::new(&format!("(?i){}$", regex_pattern)).ok()
    }

    /// Check if a path matches any of the given patterns
    fn matches_patterns(path: &str, patterns: &[regex::Regex]) -> bool {
        let normalized = path.replace('\\', "/");
        patterns.iter().any(|re| re.is_match(&normalized))
    }

    /// Check if a rule is in the always-enabled list (security rules)
    pub fn is_always_enabled(rule_id: &str) -> bool {
        RULES_ALWAYS_ENABLED.iter().any(|r| {
            rule_id == *r
                || rule_id.starts_with(&format!("{}:", r))
                || r.ends_with("*") && rule_id.starts_with(r.trim_end_matches('*'))
        })
    }

    /// Check if a finding should be suppressed
    ///
    /// Returns a SuppressionResult with details about why it was suppressed (or not).
    /// Order of checks:
    /// 1. Always-enabled rules (never suppressed by path/preset)
    /// 2. Inline suppressions
    /// 3. Global path ignores
    /// 4. Per-rule path ignores
    /// 5. Default test/example presets
    /// 6. Baseline
    pub fn check(
        &self,
        rule_id: &str,
        file_path: &Path,
        finding_line: usize,
        inline_suppressions: &[InlineSuppression],
        fingerprint: Option<&str>,
    ) -> SuppressionResult {
        let path_str = file_path.to_string_lossy();

        // 1. Check inline suppressions first (they apply regardless of always-enabled)
        for suppression in inline_suppressions {
            if suppression.applies_to(finding_line, rule_id) {
                let reason = suppression
                    .reason
                    .clone()
                    .unwrap_or_else(|| "No reason provided".to_string());
                return SuppressionResult::suppressed(
                    SuppressionSource::Inline,
                    reason,
                    format!("line {}", suppression.line),
                );
            }
        }

        // Security rules should not be suppressed by path/preset (only inline or baseline)
        let is_always_enabled = Self::is_always_enabled(rule_id);

        if !is_always_enabled {
            // 2. Check global path ignores
            if Self::matches_patterns(&path_str, &self.global_patterns) {
                for (i, pattern) in self.global_ignore_paths.iter().enumerate() {
                    if let Some(re) = self.global_patterns.get(i)
                        && re.is_match(&path_str.replace('\\', "/"))
                    {
                        return SuppressionResult::suppressed(
                            SuppressionSource::PathGlobal,
                            format!("Path matches global ignore pattern: {}", pattern),
                            pattern.clone(),
                        );
                    }
                }
            }

            // 3. Check per-rule path ignores
            if let Some(patterns) = self.rule_patterns.get(rule_id)
                && Self::matches_patterns(&path_str, patterns)
                && let Some(rule_paths) = self.rule_ignore_paths.get(rule_id)
            {
                for (i, pattern) in rule_paths.iter().enumerate() {
                    if let Some(re) = patterns.get(i)
                        && re.is_match(&path_str.replace('\\', "/"))
                    {
                        return SuppressionResult::suppressed(
                            SuppressionSource::PathRule,
                            format!("Path matches rule-specific ignore pattern: {}", pattern),
                            format!("{}:{}", rule_id, pattern),
                        );
                    }
                }
            }

            // Also check wildcard rule patterns
            for (pattern_rule_id, patterns) in &self.rule_patterns {
                if pattern_rule_id.ends_with("/*") {
                    let prefix = pattern_rule_id.trim_end_matches("/*");
                    if rule_id.starts_with(prefix)
                        && Self::matches_patterns(&path_str, patterns)
                        && let Some(rule_paths) = self.rule_ignore_paths.get(pattern_rule_id)
                        && let Some(pattern) = rule_paths.first()
                    {
                        return SuppressionResult::suppressed(
                            SuppressionSource::PathRule,
                            format!("Path matches rule-specific ignore pattern: {}", pattern),
                            format!("{}:{}", pattern_rule_id, pattern),
                        );
                    }
                }
            }

            // 4. Check default test/example presets
            if self.use_default_presets {
                if Self::matches_patterns(&path_str, &self.test_patterns) {
                    return SuppressionResult::suppressed(
                        SuppressionSource::Preset,
                        "File is in test directory (suppressed by default preset)".to_string(),
                        "test-preset".to_string(),
                    );
                }
                if Self::matches_patterns(&path_str, &self.example_patterns) {
                    return SuppressionResult::suppressed(
                        SuppressionSource::Preset,
                        "File is in example/fixture directory (suppressed by default preset)"
                            .to_string(),
                        "example-preset".to_string(),
                    );
                }
            }
        }

        // 5. Check baseline (applies to all rules including always-enabled)
        if let Some(ref baseline) = self.baseline
            && let Some(fp) = fingerprint
        {
            let fingerprint_obj = Fingerprint::from_string(fp.to_string());
            if baseline.contains_fingerprint(&fingerprint_obj) {
                return SuppressionResult::suppressed(
                    SuppressionSource::Baseline,
                    "Finding is in baseline".to_string(),
                    "baseline".to_string(),
                );
            }
        }

        // 6. Check database suppressions (applies to all rules including always-enabled)
        if let Some(ref store) = self.suppression_store
            && let Some(fp) = fingerprint
            && let Ok(Some(entry)) = store.is_suppressed(fp)
        {
            return SuppressionResult::suppressed(
                SuppressionSource::Database,
                entry.reason.clone(),
                format!("database:{}", entry.id),
            );
        }

        SuppressionResult::not_suppressed()
    }

    /// Check if a path should be completely ignored (before parsing/analysis)
    ///
    /// This is a fast path check that doesn't require inline suppressions.
    /// Only checks path-based ignores, not inline or baseline.
    pub fn should_skip_path(&self, file_path: &Path) -> bool {
        let path_str = file_path.to_string_lossy();

        // Check global path ignores
        if Self::matches_patterns(&path_str, &self.global_patterns) {
            return true;
        }

        // Check default presets (for tests/examples)
        if self.use_default_presets {
            // For path skipping, we only skip if ALL rules would be suppressed
            // Security rules can still fire, so we don't skip the path entirely
            // This is a conservative approach - we still parse the file
            // but suppress non-security findings later
            false
        } else {
            false
        }
    }

    /// Add suppression metadata to a finding's properties
    pub fn add_suppression_metadata(
        properties: &mut HashMap<String, serde_json::Value>,
        result: &SuppressionResult,
    ) {
        if result.suppressed {
            properties.insert("suppressed".to_string(), serde_json::json!(true));
            if let Some(ref reason) = result.reason {
                properties.insert("suppression_reason".to_string(), serde_json::json!(reason));
            }
            if let Some(ref source) = result.source {
                properties.insert(
                    "suppression_source".to_string(),
                    serde_json::json!(source.to_string()),
                );

                // For database suppressions, extract the suppression_id
                if *source == SuppressionSource::Database
                    && let Some(ref location) = result.location
                    && let Some(id) = location.strip_prefix("database:")
                {
                    properties.insert("suppression_id".to_string(), serde_json::json!(id));
                }
            }
            if let Some(ref location) = result.location {
                properties.insert(
                    "suppression_location".to_string(),
                    serde_json::json!(location),
                );
            }
        }
    }
}

impl Default for SuppressionEngine {
    fn default() -> Self {
        Self::new(&RulesConfig::default(), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_profile_parsing() {
        assert_eq!(Profile::from_str("fast").unwrap(), Profile::Fast);
        assert_eq!(Profile::from_str("balanced").unwrap(), Profile::Balanced);
        assert_eq!(Profile::from_str("strict").unwrap(), Profile::Strict);
        assert!(Profile::from_str("unknown").is_err());
    }

    #[test]
    fn test_rule_matching() {
        assert!(RmaTomlConfig::matches_pattern("security/xss", "*"));
        assert!(RmaTomlConfig::matches_pattern("security/xss", "security/*"));
        assert!(!RmaTomlConfig::matches_pattern(
            "generic/long",
            "security/*"
        ));
        assert!(RmaTomlConfig::matches_pattern(
            "security/xss",
            "security/xss"
        ));
    }

    #[test]
    fn test_default_config_parses() {
        let toml = RmaTomlConfig::default_toml(Profile::Balanced);
        let config: RmaTomlConfig = toml::from_str(&toml).expect("Default config should parse");
        assert_eq!(config.profiles.default, Profile::Balanced);
    }

    #[test]
    fn test_thresholds_for_profile() {
        let fast = ProfileThresholds::for_profile(Profile::Fast);
        let strict = ProfileThresholds::for_profile(Profile::Strict);

        assert!(fast.max_function_lines > strict.max_function_lines);
        assert!(fast.max_complexity > strict.max_complexity);
    }

    #[test]
    fn test_fingerprint_stable_across_line_changes() {
        // Same finding at different line numbers should yield same fingerprint
        let fp1 = Fingerprint::generate(
            "js/xss-sink",
            Path::new("src/app.js"),
            "element.textContent = userInput;",
        );
        let fp2 = Fingerprint::generate(
            "js/xss-sink",
            Path::new("src/app.js"),
            "element.textContent = userInput;",
        );

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_stable_with_whitespace_changes() {
        // Minor whitespace changes shouldn't affect fingerprint
        let fp1 = Fingerprint::generate(
            "generic/long-function",
            Path::new("src/utils.rs"),
            "fn very_long_function() {",
        );
        let fp2 = Fingerprint::generate(
            "generic/long-function",
            Path::new("src/utils.rs"),
            "fn   very_long_function()   {",
        );
        let fp3 = Fingerprint::generate(
            "generic/long-function",
            Path::new("src/utils.rs"),
            "  fn very_long_function() {  ",
        );

        assert_eq!(fp1, fp2);
        assert_eq!(fp2, fp3);
    }

    #[test]
    fn test_fingerprint_different_for_different_rules() {
        let fp1 = Fingerprint::generate("js/xss-sink", Path::new("src/app.js"), "element.x = val;");
        let fp2 = Fingerprint::generate("js/eval", Path::new("src/app.js"), "element.x = val;");

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_different_for_different_files() {
        let fp1 = Fingerprint::generate("js/xss-sink", Path::new("src/app.js"), "element.x = val;");
        let fp2 =
            Fingerprint::generate("js/xss-sink", Path::new("src/other.js"), "element.x = val;");

        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_path_normalization() {
        // Windows and Unix paths should normalize to same fingerprint
        let fp1 = Fingerprint::generate("js/xss-sink", Path::new("src/components/App.js"), "x");
        let fp2 = Fingerprint::generate("js/xss-sink", Path::new("src\\components\\App.js"), "x");

        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_effective_config_precedence() {
        // Test CLI overrides config
        let toml_config = RmaTomlConfig::default();
        let effective = EffectiveConfig::resolve(
            Some(&toml_config),
            Some(Path::new("rma.toml")),
            Some(Profile::Strict), // CLI override
            false,
        );

        assert_eq!(effective.profile, Profile::Strict);
        assert_eq!(effective.profile_source, ConfigSource::CliFlag);
    }

    #[test]
    fn test_effective_config_defaults() {
        // No config, no CLI flags = defaults
        let effective = EffectiveConfig::resolve(None, None, None, false);

        assert_eq!(effective.profile, Profile::Balanced);
        assert_eq!(effective.profile_source, ConfigSource::Default);
        assert!(effective.config_file.is_none());
    }

    #[test]
    fn test_effective_config_from_file() {
        // Config file with no CLI override
        let mut toml_config = RmaTomlConfig::default();
        toml_config.profiles.default = Profile::Fast;

        let effective =
            EffectiveConfig::resolve(Some(&toml_config), Some(Path::new("rma.toml")), None, false);

        assert_eq!(effective.profile, Profile::Fast);
        assert_eq!(effective.profile_source, ConfigSource::ConfigFile);
    }

    #[test]
    fn test_config_version_missing_warns() {
        let toml = r#"
[profiles]
default = "balanced"
"#;
        let config: RmaTomlConfig = toml::from_str(toml).unwrap();
        assert!(config.config_version.is_none());
        assert!(!config.has_version());
        assert_eq!(config.effective_version(), 1);

        let warnings = config.validate();
        assert!(
            warnings
                .iter()
                .any(|w| w.message.contains("Missing 'config_version'"))
        );
    }

    #[test]
    fn test_config_version_1_ok() {
        let toml = r#"
config_version = 1

[profiles]
default = "balanced"
"#;
        let config: RmaTomlConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.config_version, Some(1));
        assert!(config.has_version());
        assert_eq!(config.effective_version(), 1);

        let warnings = config.validate();
        assert!(
            !warnings
                .iter()
                .any(|w| w.message.contains("config_version"))
        );
    }

    #[test]
    fn test_config_version_999_fails() {
        let toml = r#"
config_version = 999

[profiles]
default = "balanced"
"#;
        let config: RmaTomlConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.config_version, Some(999));

        let warnings = config.validate();
        let error = warnings.iter().find(|w| w.level == WarningLevel::Error);
        assert!(error.is_some());
        assert!(
            error
                .unwrap()
                .message
                .contains("Unsupported config version: 999")
        );
    }

    #[test]
    fn test_default_toml_includes_version() {
        let toml = RmaTomlConfig::default_toml(Profile::Balanced);
        assert!(toml.contains("config_version = 1"));

        // Verify it parses correctly
        let config: RmaTomlConfig = toml::from_str(&toml).unwrap();
        assert_eq!(config.config_version, Some(1));
    }

    #[test]
    fn test_ruleset_security() {
        let toml = r#"
config_version = 1

[rulesets]
security = ["js/innerhtml-xss", "js/timer-string-eval"]
maintainability = ["generic/long-function"]

[rules]
enable = ["*"]
"#;
        let config: RmaTomlConfig = toml::from_str(toml).unwrap();

        // With security ruleset, only security rules are enabled
        assert!(config.is_rule_enabled_with_ruleset("js/innerhtml-xss", Some("security")));
        assert!(config.is_rule_enabled_with_ruleset("js/timer-string-eval", Some("security")));
        assert!(!config.is_rule_enabled_with_ruleset("generic/long-function", Some("security")));

        // Without ruleset, normal enable/disable applies
        assert!(config.is_rule_enabled("generic/long-function"));
    }

    #[test]
    fn test_ruleset_with_disable() {
        let toml = r#"
config_version = 1

[rulesets]
security = ["js/innerhtml-xss", "js/timer-string-eval"]

[rules]
enable = ["*"]
disable = ["js/timer-string-eval"]
"#;
        let config: RmaTomlConfig = toml::from_str(toml).unwrap();

        // Disable takes precedence even with ruleset
        assert!(config.is_rule_enabled_with_ruleset("js/innerhtml-xss", Some("security")));
        assert!(!config.is_rule_enabled_with_ruleset("js/timer-string-eval", Some("security")));
    }

    #[test]
    fn test_get_ruleset_names() {
        let toml = r#"
config_version = 1

[rulesets]
security = ["js/innerhtml-xss"]
maintainability = ["generic/long-function"]
"#;
        let config: RmaTomlConfig = toml::from_str(toml).unwrap();
        let names = config.get_ruleset_names();

        assert!(names.contains(&"security".to_string()));
        assert!(names.contains(&"maintainability".to_string()));
    }

    #[test]
    fn test_default_toml_includes_rulesets() {
        let toml = RmaTomlConfig::default_toml(Profile::Balanced);
        assert!(toml.contains("[rulesets]"));
        assert!(toml.contains("security = "));
        assert!(toml.contains("maintainability = "));
    }

    #[test]
    fn test_inline_suppression_next_line() {
        let suppression = InlineSuppression::parse(
            "// rma-ignore-next-line js/innerhtml-xss reason=\"sanitized input\"",
            10,
        );
        assert!(suppression.is_some());
        let s = suppression.unwrap();
        assert_eq!(s.rule_id, "js/innerhtml-xss");
        assert_eq!(s.reason, Some("sanitized input".to_string()));
        assert_eq!(s.line, 10);
        assert_eq!(s.suppression_type, SuppressionType::NextLine);

        // Should apply to line 11
        assert!(s.applies_to(11, "js/innerhtml-xss"));
        // Should NOT apply to line 12
        assert!(!s.applies_to(12, "js/innerhtml-xss"));
        // Should NOT apply to other rules
        assert!(!s.applies_to(11, "js/console-log"));
    }

    #[test]
    fn test_inline_suppression_block() {
        let suppression = InlineSuppression::parse(
            "// rma-ignore generic/long-function reason=\"legacy code\"",
            5,
        );
        assert!(suppression.is_some());
        let s = suppression.unwrap();
        assert_eq!(s.rule_id, "generic/long-function");
        assert_eq!(s.suppression_type, SuppressionType::Block);

        // Should apply to line 5 and beyond
        assert!(s.applies_to(5, "generic/long-function"));
        assert!(s.applies_to(10, "generic/long-function"));
        assert!(s.applies_to(100, "generic/long-function"));
    }

    #[test]
    fn test_inline_suppression_without_reason() {
        let suppression = InlineSuppression::parse("// rma-ignore-next-line js/console-log", 1);
        assert!(suppression.is_some());
        let s = suppression.unwrap();
        assert_eq!(s.rule_id, "js/console-log");
        assert!(s.reason.is_none());
    }

    #[test]
    fn test_inline_suppression_python_style() {
        let suppression = InlineSuppression::parse(
            "# rma-ignore-next-line python/hardcoded-secret reason=\"test data\"",
            3,
        );
        assert!(suppression.is_some());
        let s = suppression.unwrap();
        assert_eq!(s.rule_id, "python/hardcoded-secret");
        assert_eq!(s.reason, Some("test data".to_string()));
    }

    #[test]
    fn test_inline_suppression_validation_strict() {
        let s = InlineSuppression {
            rule_id: "js/xss".to_string(),
            reason: None,
            line: 1,
            suppression_type: SuppressionType::NextLine,
        };

        // Without reason, strict validation fails
        assert!(s.validate(true).is_err());
        // Without reason, non-strict validation passes
        assert!(s.validate(false).is_ok());

        let s_with_reason = InlineSuppression {
            rule_id: "js/xss".to_string(),
            reason: Some("approved".to_string()),
            line: 1,
            suppression_type: SuppressionType::NextLine,
        };

        // With reason, both pass
        assert!(s_with_reason.validate(true).is_ok());
        assert!(s_with_reason.validate(false).is_ok());
    }

    #[test]
    fn test_parse_inline_suppressions() {
        let content = r#"
function foo() {
    // rma-ignore-next-line js/console-log reason="debugging"
    console.log("test");

    // rma-ignore generic/long-function reason="complex algorithm"
    // ... lots of code ...
}
"#;
        let suppressions = parse_inline_suppressions(content);
        assert_eq!(suppressions.len(), 2);
        assert_eq!(suppressions[0].rule_id, "js/console-log");
        assert_eq!(suppressions[1].rule_id, "generic/long-function");
    }

    #[test]
    fn test_suppression_does_not_affect_other_rules() {
        let suppression = InlineSuppression::parse(
            "// rma-ignore-next-line js/innerhtml-xss reason=\"safe\"",
            10,
        )
        .unwrap();

        // Applies to the specific rule
        assert!(suppression.applies_to(11, "js/innerhtml-xss"));
        // Does NOT apply to other rules
        assert!(!suppression.applies_to(11, "js/console-log"));
        assert!(!suppression.applies_to(11, "generic/long-function"));
    }

    // =========================================================================
    // SUPPRESSION ENGINE TESTS
    // =========================================================================

    #[test]
    fn test_suppression_engine_global_path_ignore() {
        let rules_config = RulesConfig {
            ignore_paths: vec!["**/vendor/**".to_string(), "**/generated/**".to_string()],
            ..Default::default()
        };

        let engine = SuppressionEngine::new(&rules_config, false);

        // Should be suppressed
        let result = engine.check(
            "generic/long-function",
            Path::new("src/vendor/lib.js"),
            10,
            &[],
            None,
        );
        assert!(result.suppressed);
        assert_eq!(result.source, Some(SuppressionSource::PathGlobal));

        // Should NOT be suppressed
        let result = engine.check(
            "generic/long-function",
            Path::new("src/app.js"),
            10,
            &[],
            None,
        );
        assert!(!result.suppressed);
    }

    #[test]
    fn test_suppression_engine_per_rule_path_ignore() {
        let rules_config = RulesConfig {
            ignore_paths_by_rule: HashMap::from([(
                "generic/long-function".to_string(),
                vec!["**/tests/**".to_string()],
            )]),
            ..Default::default()
        };

        let engine = SuppressionEngine::new(&rules_config, false);

        // Should be suppressed for this specific rule in tests
        let result = engine.check(
            "generic/long-function",
            Path::new("src/tests/test_app.js"),
            10,
            &[],
            None,
        );
        assert!(result.suppressed);
        assert_eq!(result.source, Some(SuppressionSource::PathRule));

        // Should NOT be suppressed for a different rule in tests
        let result = engine.check(
            "js/console-log",
            Path::new("src/tests/test_app.js"),
            10,
            &[],
            None,
        );
        assert!(!result.suppressed);
    }

    #[test]
    fn test_suppression_engine_inline_suppression() {
        let rules_config = RulesConfig::default();
        let engine = SuppressionEngine::new(&rules_config, false);

        let inline_suppressions = vec![InlineSuppression {
            rule_id: "js/console-log".to_string(),
            reason: Some("debug output".to_string()),
            line: 10,
            suppression_type: SuppressionType::NextLine,
        }];

        // Should be suppressed by inline comment
        let result = engine.check(
            "js/console-log",
            Path::new("src/app.js"),
            11, // Line after the suppression comment
            &inline_suppressions,
            None,
        );
        assert!(result.suppressed);
        assert_eq!(result.source, Some(SuppressionSource::Inline));
        assert_eq!(result.reason, Some("debug output".to_string()));

        // Should NOT be suppressed for different line
        let result = engine.check(
            "js/console-log",
            Path::new("src/app.js"),
            12,
            &inline_suppressions,
            None,
        );
        assert!(!result.suppressed);
    }

    #[test]
    fn test_suppression_engine_default_presets() {
        let rules_config = RulesConfig::default();
        let engine = SuppressionEngine::new(&rules_config, true); // Enable presets

        // Test files should be suppressed
        let result = engine.check(
            "generic/long-function",
            Path::new("src/tests/test_app.rs"),
            10,
            &[],
            None,
        );
        assert!(result.suppressed);
        assert_eq!(result.source, Some(SuppressionSource::Preset));

        // .test.ts files should be suppressed
        let result = engine.check(
            "js/console-log",
            Path::new("src/app.test.ts"),
            10,
            &[],
            None,
        );
        assert!(result.suppressed);

        // Example files should be suppressed
        let result = engine.check(
            "generic/long-function",
            Path::new("examples/demo.rs"),
            10,
            &[],
            None,
        );
        assert!(result.suppressed);

        // Regular source files should NOT be suppressed
        let result = engine.check(
            "generic/long-function",
            Path::new("src/lib.rs"),
            10,
            &[],
            None,
        );
        assert!(!result.suppressed);
    }

    #[test]
    fn test_suppression_engine_security_rules_not_suppressed_by_preset() {
        let rules_config = RulesConfig::default();
        let engine = SuppressionEngine::new(&rules_config, true); // Enable presets

        // Security rules should NOT be suppressed by preset in test files
        let result = engine.check(
            "rust/command-injection",
            Path::new("src/tests/test_app.rs"),
            10,
            &[],
            None,
        );
        assert!(!result.suppressed);

        let result = engine.check(
            "generic/hardcoded-secret",
            Path::new("examples/demo.py"),
            10,
            &[],
            None,
        );
        assert!(!result.suppressed);

        let result = engine.check(
            "python/shell-injection",
            Path::new("tests/test_shell.py"),
            10,
            &[],
            None,
        );
        assert!(!result.suppressed);
    }

    #[test]
    fn test_suppression_engine_security_rules_can_be_suppressed_inline() {
        let rules_config = RulesConfig::default();
        let engine = SuppressionEngine::new(&rules_config, true);

        let inline_suppressions = vec![InlineSuppression {
            rule_id: "rust/command-injection".to_string(),
            reason: Some("sanitized input validated upstream".to_string()),
            line: 10,
            suppression_type: SuppressionType::NextLine,
        }];

        // Security rules CAN be suppressed by inline comment
        let result = engine.check(
            "rust/command-injection",
            Path::new("src/app.rs"),
            11,
            &inline_suppressions,
            None,
        );
        assert!(result.suppressed);
        assert_eq!(result.source, Some(SuppressionSource::Inline));
    }

    #[test]
    fn test_suppression_engine_is_always_enabled() {
        assert!(SuppressionEngine::is_always_enabled(
            "rust/command-injection"
        ));
        assert!(SuppressionEngine::is_always_enabled(
            "python/shell-injection"
        ));
        assert!(SuppressionEngine::is_always_enabled(
            "generic/hardcoded-secret"
        ));
        assert!(SuppressionEngine::is_always_enabled("go/command-injection"));
        assert!(SuppressionEngine::is_always_enabled(
            "java/command-execution"
        ));
        assert!(SuppressionEngine::is_always_enabled(
            "js/dynamic-code-execution"
        ));

        // These should NOT be always-enabled
        assert!(!SuppressionEngine::is_always_enabled(
            "generic/long-function"
        ));
        assert!(!SuppressionEngine::is_always_enabled("js/console-log"));
        assert!(!SuppressionEngine::is_always_enabled("rust/unsafe-block"));
    }

    #[test]
    fn test_suppression_engine_add_metadata() {
        let result = SuppressionResult::suppressed(
            SuppressionSource::Inline,
            "debug output".to_string(),
            "line 10".to_string(),
        );

        let mut properties = HashMap::new();
        SuppressionEngine::add_suppression_metadata(&mut properties, &result);

        assert_eq!(properties.get("suppressed"), Some(&serde_json::json!(true)));
        assert_eq!(
            properties.get("suppression_reason"),
            Some(&serde_json::json!("debug output"))
        );
        assert_eq!(
            properties.get("suppression_source"),
            Some(&serde_json::json!("inline"))
        );
        assert_eq!(
            properties.get("suppression_location"),
            Some(&serde_json::json!("line 10"))
        );
    }

    #[test]
    fn test_suppression_result_not_suppressed() {
        let result = SuppressionResult::not_suppressed();
        assert!(!result.suppressed);
        assert!(result.reason.is_none());
        assert!(result.source.is_none());
        assert!(result.location.is_none());
    }

    #[test]
    fn test_rules_config_with_ignore_paths() {
        let toml = r#"
config_version = 1

[rules]
enable = ["*"]
disable = []
ignore_paths = ["**/vendor/**", "**/generated/**"]

[rules.ignore_paths_by_rule]
"generic/long-function" = ["**/tests/**", "**/examples/**"]
"js/console-log" = ["**/debug/**"]
"#;
        let config: RmaTomlConfig = toml::from_str(toml).unwrap();

        assert_eq!(config.rules.ignore_paths.len(), 2);
        assert!(
            config
                .rules
                .ignore_paths
                .contains(&"**/vendor/**".to_string())
        );
        assert!(
            config
                .rules
                .ignore_paths
                .contains(&"**/generated/**".to_string())
        );

        assert_eq!(config.rules.ignore_paths_by_rule.len(), 2);
        assert!(
            config
                .rules
                .ignore_paths_by_rule
                .contains_key("generic/long-function")
        );
        assert!(
            config
                .rules
                .ignore_paths_by_rule
                .contains_key("js/console-log")
        );
    }
}
