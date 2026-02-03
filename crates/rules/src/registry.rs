//! Rule registry - central storage and lookup for rules

use crate::{Result, Rule, RuleRunner};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use tracing::info;

/// Global rule registry
static REGISTRY: Lazy<RwLock<RuleRegistry>> = Lazy::new(|| RwLock::new(RuleRegistry::new()));

/// Rule registry for storing and looking up rules
#[derive(Debug, Default)]
pub struct RuleRegistry {
    /// All loaded rules by ID
    rules_by_id: HashMap<String, Rule>,

    /// Rules indexed by language
    rules_by_language: HashMap<String, Vec<String>>,

    /// Rules indexed by category
    rules_by_category: HashMap<String, Vec<String>>,

    /// Source directories for rules
    rule_dirs: Vec<PathBuf>,
}

impl RuleRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule to the registry
    pub fn add_rule(&mut self, rule: Rule) {
        let id = rule.id.clone();

        // Index by language
        for lang in &rule.languages {
            self.rules_by_language
                .entry(lang.to_lowercase())
                .or_default()
                .push(id.clone());
        }

        // Index by category
        let category = rule.category().to_string();
        self.rules_by_category
            .entry(category)
            .or_default()
            .push(id.clone());

        // Store rule
        self.rules_by_id.insert(id, rule);
    }

    /// Add multiple rules
    pub fn add_rules(&mut self, rules: Vec<Rule>) {
        for rule in rules {
            self.add_rule(rule);
        }
    }

    /// Get a rule by ID
    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.rules_by_id.get(id)
    }

    /// Get all rules for a language
    pub fn for_language(&self, lang: &str) -> Vec<&Rule> {
        let lang_lower = lang.to_lowercase();
        self.rules_by_language
            .get(&lang_lower)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.rules_by_id.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all rules for a category
    pub fn for_category(&self, category: &str) -> Vec<&Rule> {
        self.rules_by_category
            .get(category)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.rules_by_id.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all rules
    pub fn all_rules(&self) -> Vec<&Rule> {
        self.rules_by_id.values().collect()
    }

    /// Get total number of rules
    pub fn count(&self) -> usize {
        self.rules_by_id.len()
    }

    /// Get languages with rules
    pub fn languages(&self) -> Vec<&str> {
        self.rules_by_language.keys().map(|s| s.as_str()).collect()
    }

    /// Get categories with rules
    pub fn categories(&self) -> Vec<&str> {
        self.rules_by_category.keys().map(|s| s.as_str()).collect()
    }

    /// Create a rule runner for a specific language
    pub fn runner_for_language(&self, lang: &str) -> Result<RuleRunner> {
        let rules: Vec<Rule> = self.for_language(lang).into_iter().cloned().collect();
        RuleRunner::new(rules)
    }

    /// Create a rule runner for all rules
    pub fn runner(&self) -> Result<RuleRunner> {
        let rules: Vec<Rule> = self.all_rules().into_iter().cloned().collect();
        RuleRunner::new(rules)
    }

    /// Clear all rules
    pub fn clear(&mut self) {
        self.rules_by_id.clear();
        self.rules_by_language.clear();
        self.rules_by_category.clear();
    }

    /// Load rules from a directory
    pub fn load_from_dir(&mut self, dir: PathBuf) -> Result<usize> {
        let rules = crate::load_rules_from_dir(&dir)?;
        let count = rules.len();
        self.add_rules(rules);
        self.rule_dirs.push(dir);
        info!("Loaded {} rules into registry", count);
        Ok(count)
    }

    /// Get statistics about the registry
    pub fn stats(&self) -> RegistryStats {
        RegistryStats {
            total_rules: self.rules_by_id.len(),
            languages: self.rules_by_language.len(),
            categories: self.rules_by_category.len(),
            rules_per_language: self
                .rules_by_language
                .iter()
                .map(|(k, v)| (k.clone(), v.len()))
                .collect(),
        }
    }
}

/// Statistics about the rule registry
#[derive(Debug, Clone)]
pub struct RegistryStats {
    pub total_rules: usize,
    pub languages: usize,
    pub categories: usize,
    pub rules_per_language: HashMap<String, usize>,
}

// Global registry functions

/// Get a reference to the global registry
pub fn global_registry() -> &'static RwLock<RuleRegistry> {
    &REGISTRY
}

/// Load rules into the global registry from a directory
pub fn load_global_rules(dir: PathBuf) -> Result<usize> {
    let mut registry = REGISTRY.write().unwrap();
    registry.load_from_dir(dir)
}

/// Get a rule from the global registry
pub fn get_rule(id: &str) -> Option<Rule> {
    let registry = REGISTRY.read().unwrap();
    registry.get(id).cloned()
}

/// Get rules for a language from the global registry
pub fn rules_for_language(lang: &str) -> Vec<Rule> {
    let registry = REGISTRY.read().unwrap();
    registry.for_language(lang).into_iter().cloned().collect()
}

/// Create a runner from the global registry
pub fn create_runner(lang: Option<&str>) -> Result<RuleRunner> {
    let registry = REGISTRY.read().unwrap();
    match lang {
        Some(l) => registry.runner_for_language(l),
        None => registry.runner(),
    }
}

/// Get global registry statistics
pub fn registry_stats() -> RegistryStats {
    let registry = REGISTRY.read().unwrap();
    registry.stats()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{RuleMetadata, RuleMode, Severity};

    fn create_test_rule(id: &str, languages: Vec<&str>, category: &str) -> Rule {
        Rule {
            id: id.to_string(),
            message: "Test".to_string(),
            severity: Severity::Warning,
            languages: languages.into_iter().map(String::from).collect(),
            mode: RuleMode::Search,
            pattern: Some("test".to_string()),
            pattern_either: None,
            patterns: None,
            pattern_not: None,
            pattern_regex: None,
            pattern_sources: None,
            pattern_sinks: None,
            pattern_sanitizers: None,
            pattern_propagators: None,
            metadata: RuleMetadata {
                category: Some(category.to_string()),
                ..Default::default()
            },
            fix: None,
            fix_regex: None,
            min_version: None,
            options: None,
        }
    }

    #[test]
    fn test_registry_add_and_lookup() {
        let mut registry = RuleRegistry::new();

        registry.add_rule(create_test_rule("rule1", vec!["python"], "security"));
        registry.add_rule(create_test_rule(
            "rule2",
            vec!["python", "javascript"],
            "security",
        ));
        registry.add_rule(create_test_rule("rule3", vec!["rust"], "performance"));

        assert_eq!(registry.count(), 3);
        assert!(registry.get("rule1").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_registry_by_language() {
        let mut registry = RuleRegistry::new();

        registry.add_rule(create_test_rule("py1", vec!["python"], "security"));
        registry.add_rule(create_test_rule("py2", vec!["python"], "security"));
        registry.add_rule(create_test_rule("js1", vec!["javascript"], "security"));

        let py_rules = registry.for_language("python");
        assert_eq!(py_rules.len(), 2);

        let js_rules = registry.for_language("javascript");
        assert_eq!(js_rules.len(), 1);
    }

    #[test]
    fn test_registry_by_category() {
        let mut registry = RuleRegistry::new();

        registry.add_rule(create_test_rule("sec1", vec!["python"], "security"));
        registry.add_rule(create_test_rule("sec2", vec!["python"], "security"));
        registry.add_rule(create_test_rule("perf1", vec!["python"], "performance"));

        let sec_rules = registry.for_category("security");
        assert_eq!(sec_rules.len(), 2);

        let perf_rules = registry.for_category("performance");
        assert_eq!(perf_rules.len(), 1);
    }

    #[test]
    fn test_registry_stats() {
        let mut registry = RuleRegistry::new();

        registry.add_rule(create_test_rule("r1", vec!["python"], "security"));
        registry.add_rule(create_test_rule("r2", vec!["javascript"], "security"));

        let stats = registry.stats();
        assert_eq!(stats.total_rules, 2);
        assert_eq!(stats.languages, 2);
    }
}
