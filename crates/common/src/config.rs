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
            _ => Err(format!("Unknown profile: {}. Use: fast, balanced, strict", s)),
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

/// Complete RMA TOML configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RmaTomlConfig {
    /// Scan path configuration
    #[serde(default)]
    pub scan: ScanConfig,

    /// Rules configuration
    #[serde(default)]
    pub rules: RulesConfig,

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
}

impl RmaTomlConfig {
    /// Load configuration from file
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        toml::from_str(&content).map_err(|e| format!("Failed to parse TOML: {}", e))
    }

    /// Find and load configuration from standard locations
    pub fn discover(start_path: &Path) -> Option<(PathBuf, Self)> {
        let candidates = [
            start_path.join("rma.toml"),
            start_path.join(".rma/rma.toml"),
            start_path.join(".rma.toml"),
        ];

        for candidate in &candidates {
            if candidate.exists() {
                if let Ok(config) = Self::load(candidate) {
                    return Some((candidate.clone(), config));
                }
            }
        }

        // Check parent directories up to 5 levels
        let mut current = start_path.to_path_buf();
        for _ in 0..5 {
            if let Some(parent) = current.parent() {
                let config_path = parent.join("rma.toml");
                if config_path.exists() {
                    if let Ok(config) = Self::load(&config_path) {
                        return Some((config_path, config));
                    }
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
        for (rule_id, _) in &self.severity {
            if rule_id.is_empty() {
                warnings.push(ConfigWarning {
                    level: WarningLevel::Error,
                    message: "Empty rule ID in severity overrides".to_string(),
                });
            }
        }

        warnings
    }

    /// Check if a rule is enabled
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        // Check if explicitly disabled
        for pattern in &self.rules.disable {
            if Self::matches_pattern(rule_id, pattern) {
                return false;
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

        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 2];
            return rule_id.starts_with(prefix);
        }

        rule_id == pattern
    }

    fn matches_glob(path: &str, pattern: &str) -> bool {
        // Simple glob matching (supports * and **)
        let pattern = pattern.replace("**", "§").replace('*', "[^/]*").replace('§', ".*");
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

/// Baseline entry for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub rule_id: String,
    pub file: PathBuf,
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

    /// Check if a finding is in the baseline
    pub fn contains(&self, rule_id: &str, file: &Path, fingerprint: &str) -> bool {
        self.entries.iter().any(|e| {
            e.rule_id == rule_id && e.file == file && e.fingerprint == fingerprint
        })
    }

    /// Add a finding to the baseline
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
        assert!(!RmaTomlConfig::matches_pattern("generic/long", "security/*"));
        assert!(RmaTomlConfig::matches_pattern("security/xss", "security/xss"));
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
}
