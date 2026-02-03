//! Semgrep rule integration
//!
//! This module provides integration with the Semgrep rule format,
//! allowing RMA to use the thousands of community-vetted rules from
//! the semgrep-rules repository.
//!
//! # Usage
//!
//! ```ignore
//! use rma_analyzer::semgrep::{SemgrepRuleEngine, RuleEngineConfig};
//!
//! // Load rules from semgrep-rules directory
//! let config = RuleEngineConfig::default()
//!     .with_semgrep_dir("external/semgrep-rules");
//!
//! let engine = SemgrepRuleEngine::new(config)?;
//!
//! // Check a file
//! let findings = engine.check_file(path, &content, language)?;
//! ```

use rma_common::{Finding, Language};
use rma_rules::load_embedded_rules;
use rma_rules::{Rule, RuleRegistry, RuleRunner, load_rules_from_dir};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tracing::{debug, info, warn};

/// Configuration for the Semgrep rule engine
#[derive(Debug, Clone)]
pub struct RuleEngineConfig {
    /// Directory containing semgrep-rules
    pub semgrep_dir: Option<PathBuf>,

    /// Additional custom rule directories
    pub custom_dirs: Vec<PathBuf>,

    /// Languages to load rules for (empty = all)
    pub languages: Vec<String>,

    /// Categories to include (empty = all)
    pub categories: Vec<String>,

    /// Whether to include taint-mode rules
    pub include_taint: bool,

    /// Maximum rules to load (0 = unlimited)
    pub max_rules: usize,
}

impl Default for RuleEngineConfig {
    fn default() -> Self {
        Self {
            semgrep_dir: None,
            custom_dirs: vec![],
            languages: vec![],
            categories: vec!["security".to_string()],
            include_taint: true,
            max_rules: 0,
        }
    }
}

impl RuleEngineConfig {
    /// Set the semgrep-rules directory
    pub fn with_semgrep_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.semgrep_dir = Some(dir.into());
        self
    }

    /// Add a custom rules directory
    pub fn add_custom_dir<P: Into<PathBuf>>(mut self, dir: P) -> Self {
        self.custom_dirs.push(dir.into());
        self
    }

    /// Filter to specific languages
    pub fn for_languages(mut self, langs: Vec<String>) -> Self {
        self.languages = langs;
        self
    }

    /// Filter to specific categories
    pub fn for_categories(mut self, cats: Vec<String>) -> Self {
        self.categories = cats;
        self
    }

    /// Set maximum rules to load
    pub fn max_rules(mut self, max: usize) -> Self {
        self.max_rules = max;
        self
    }
}

/// Semgrep-based rule engine for security scanning
pub struct SemgrepRuleEngine {
    /// Rule registry
    registry: RuleRegistry,

    /// Compiled rule runner
    runner: RuleRunner,

    /// Configuration
    #[allow(dead_code)]
    config: RuleEngineConfig,
}

impl SemgrepRuleEngine {
    /// Create a new rule engine with the given configuration
    pub fn new(config: RuleEngineConfig) -> anyhow::Result<Self> {
        let mut registry = RuleRegistry::new();
        let mut all_rules = Vec::new();

        // Load from semgrep-rules directory
        if let Some(ref semgrep_dir) = config.semgrep_dir {
            if semgrep_dir.exists() {
                info!(
                    "Loading rules from semgrep-rules: {}",
                    semgrep_dir.display()
                );
                let rules = load_semgrep_rules(semgrep_dir, &config)?;
                info!("Loaded {} rules from semgrep-rules", rules.len());
                all_rules.extend(rules);
            } else {
                warn!(
                    "Semgrep rules directory not found: {}",
                    semgrep_dir.display()
                );
            }
        }

        // Load from custom directories
        for dir in &config.custom_dirs {
            if dir.exists() {
                match load_rules_from_dir(dir) {
                    Ok(rules) => {
                        info!("Loaded {} rules from {}", rules.len(), dir.display());
                        all_rules.extend(rules);
                    }
                    Err(e) => {
                        warn!("Failed to load rules from {}: {}", dir.display(), e);
                    }
                }
            }
        }

        // Apply max_rules limit
        if config.max_rules > 0 && all_rules.len() > config.max_rules {
            all_rules.truncate(config.max_rules);
        }

        // Add to registry
        let rule_count = all_rules.len();
        registry.add_rules(all_rules.clone());

        // Create runner
        let runner = RuleRunner::new(all_rules)?;

        info!("SemgrepRuleEngine initialized with {} rules", rule_count);

        Ok(Self {
            registry,
            runner,
            config,
        })
    }

    /// Create with default semgrep-rules location
    pub fn with_default_rules() -> anyhow::Result<Self> {
        let semgrep_dir = PathBuf::from("external/semgrep-rules");
        if !semgrep_dir.exists() {
            anyhow::bail!(
                "Semgrep rules not found. Run: git clone --depth 1 \
                https://github.com/semgrep/semgrep-rules.git external/semgrep-rules"
            );
        }

        Self::new(RuleEngineConfig::default().with_semgrep_dir(semgrep_dir))
    }

    /// Create with embedded rules (compiled into binary at build time)
    /// This is the recommended way to use the rule engine - no external files needed.
    pub fn with_embedded_rules() -> anyhow::Result<Self> {
        let rules = load_embedded_rules()
            .map_err(|e| anyhow::anyhow!("Failed to load embedded rules: {}", e))?;

        let rule_count = rules.len();
        info!("Loading {} embedded rules into engine", rule_count);

        let mut registry = RuleRegistry::new();
        registry.add_rules(rules.clone());

        let runner = RuleRunner::new(rules)?;

        info!(
            "SemgrepRuleEngine initialized with {} embedded rules",
            rule_count
        );

        Ok(Self {
            registry,
            runner,
            config: RuleEngineConfig::default(),
        })
    }

    /// Get number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.runner.rule_count()
    }

    /// Get rules for a specific language
    pub fn rules_for_language(&self, lang: &str) -> Vec<&Rule> {
        self.registry.for_language(lang)
    }

    /// Check a file and return findings
    pub fn check_file(&self, path: &Path, content: &str, language: Language) -> Vec<Finding> {
        self.runner.check(content, path, language)
    }

    /// Check multiple files in parallel
    pub fn check_files(&self, files: &[(PathBuf, String, Language)]) -> Vec<Finding> {
        use rayon::prelude::*;

        files
            .par_iter()
            .flat_map(|(path, content, lang)| self.runner.check(content, path, *lang))
            .collect()
    }

    /// Get registry statistics
    pub fn stats(&self) -> rma_rules::RegistryStats {
        self.registry.stats()
    }
}

/// Load rules from the semgrep-rules directory structure
fn load_semgrep_rules(base_dir: &Path, config: &RuleEngineConfig) -> anyhow::Result<Vec<Rule>> {
    let mut all_rules = Vec::new();

    // Language directories in semgrep-rules
    let lang_dirs = [
        ("python", vec!["python", "py"]),
        ("javascript", vec!["javascript", "js"]),
        ("typescript", vec!["typescript", "ts"]),
        ("java", vec!["java"]),
        ("go", vec!["go"]),
        ("ruby", vec!["ruby", "rb"]),
        ("rust", vec!["rust", "rs"]),
        ("c", vec!["c"]),
        ("csharp", vec!["csharp", "cs"]),
        ("php", vec!["php"]),
        ("kotlin", vec!["kotlin", "kt"]),
        ("scala", vec!["scala"]),
        ("swift", vec!["swift"]),
        ("generic", vec!["generic"]),
    ];

    for (dir_name, lang_aliases) in &lang_dirs {
        // Check if we should load this language
        if !config.languages.is_empty() {
            let should_load = lang_aliases.iter().any(|alias| {
                config
                    .languages
                    .iter()
                    .any(|l| l.eq_ignore_ascii_case(alias))
            });
            if !should_load {
                continue;
            }
        }

        let lang_dir = base_dir.join(dir_name);
        if !lang_dir.exists() {
            continue;
        }

        match load_rules_from_dir(&lang_dir) {
            Ok(rules) => {
                // Filter by category if needed
                let filtered: Vec<Rule> = if config.categories.is_empty() {
                    rules
                } else {
                    rules
                        .into_iter()
                        .filter(|r| {
                            let cat = r.category().to_lowercase();
                            config
                                .categories
                                .iter()
                                .any(|c| cat.contains(&c.to_lowercase()))
                        })
                        .collect()
                };

                // Filter taint rules if needed
                let filtered: Vec<Rule> = if config.include_taint {
                    filtered
                } else {
                    filtered
                        .into_iter()
                        .filter(|r| !r.is_taint_mode())
                        .collect()
                };

                debug!(
                    "Loaded {} rules for {} (filtered from {})",
                    filtered.len(),
                    dir_name,
                    filtered.len()
                );
                all_rules.extend(filtered);
            }
            Err(e) => {
                warn!("Failed to load {} rules: {}", dir_name, e);
            }
        }
    }

    Ok(all_rules)
}

/// Adapter to use SemgrepRuleEngine as an analyzer Rule
pub struct SemgrepRuleAdapter {
    engine: Arc<SemgrepRuleEngine>,
}

impl SemgrepRuleAdapter {
    pub fn new(engine: Arc<SemgrepRuleEngine>) -> Self {
        Self { engine }
    }
}

impl crate::rules::Rule for SemgrepRuleAdapter {
    fn id(&self) -> &str {
        "semgrep/rules"
    }

    fn description(&self) -> &str {
        "Community-vetted security rules from semgrep-rules"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true // We filter internally based on the rule's language
    }

    fn check(&self, parsed: &rma_parser::ParsedFile) -> Vec<Finding> {
        self.engine
            .check_file(&parsed.path, &parsed.content, parsed.language)
    }
}

/// Embedded rules adapter - automatically loads pre-compiled rules from binary
///
/// This adapter loads rules that were compiled into the binary at build time,
/// providing zero-filesystem-access rule execution. Rules are loaded lazily
/// on first use and cached for subsequent files.
pub struct EmbeddedRulesRule {
    engine: OnceLock<Arc<SemgrepRuleEngine>>,
}

impl EmbeddedRulesRule {
    /// Create a new embedded rules adapter
    /// Note: Rules are loaded lazily on first check() call
    pub fn new() -> Self {
        Self {
            engine: OnceLock::new(),
        }
    }

    /// Get or initialize the embedded rule engine
    fn get_engine(&self) -> Option<&Arc<SemgrepRuleEngine>> {
        self.engine.get_or_init(|| {
            match SemgrepRuleEngine::with_embedded_rules() {
                Ok(engine) => {
                    info!(
                        "Embedded rules engine initialized with {} rules",
                        engine.rule_count()
                    );
                    Arc::new(engine)
                }
                Err(e) => {
                    warn!("Failed to initialize embedded rules: {}", e);
                    // Return empty engine on failure
                    Arc::new(SemgrepRuleEngine::new(RuleEngineConfig::default()).unwrap())
                }
            }
        });
        self.engine.get()
    }
}

impl Default for EmbeddedRulesRule {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::rules::Rule for EmbeddedRulesRule {
    fn id(&self) -> &str {
        "embedded/security-rules"
    }

    fn description(&self) -> &str {
        "1100+ community-vetted security rules compiled into the binary"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true // Embedded rules cover all supported languages
    }

    fn check(&self, parsed: &rma_parser::ParsedFile) -> Vec<Finding> {
        if let Some(engine) = self.get_engine() {
            engine.check_file(&parsed.path, &parsed.content, parsed.language)
        } else {
            vec![] // Gracefully degrade if engine fails to load
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = RuleEngineConfig::default()
            .with_semgrep_dir("/tmp/rules")
            .for_languages(vec!["python".to_string()])
            .for_categories(vec!["security".to_string()])
            .max_rules(100);

        assert_eq!(config.semgrep_dir, Some(PathBuf::from("/tmp/rules")));
        assert_eq!(config.languages, vec!["python".to_string()]);
        assert_eq!(config.max_rules, 100);
    }

    #[test]
    fn test_engine_without_rules() {
        // Should work with empty config (no rules loaded)
        let config = RuleEngineConfig::default();
        let engine = SemgrepRuleEngine::new(config);
        assert!(engine.is_ok());
        assert_eq!(engine.unwrap().rule_count(), 0);
    }
}
