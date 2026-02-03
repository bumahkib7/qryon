//! Embedded rule loader - loads pre-compiled rules from binary blob
//!
//! Rules are compiled at build time by `build.rs` and embedded in the binary.
//! This provides zero-filesystem-access rule loading for the CLI.
//!
//! The build-time translator converts Semgrep patterns into optimal matching strategies:
//! - TreeSitterQuery: Fast AST queries for simple patterns (~70% of rules)
//! - LiteralSearch: String matching for literal patterns
//! - Regex: Pre-validated regex patterns
//! - AstWalker: Complex patterns requiring traversal
//! - Taint: Data flow tracking rules

use crate::{Result, Rule, RuleError};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use tracing::{debug, info};

/// Compiled rules embedded at build time
const COMPILED_RULES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/compiled_rules.bin"));

/// Cached deserialized ruleset (loaded lazily on first access)
static RULESET_CACHE: Lazy<RwLock<Option<CompiledRuleSet>>> = Lazy::new(|| RwLock::new(None));

// =============================================================================
// COMPILED RULE FORMAT (must match build.rs)
// =============================================================================

/// Matching strategy determined at build time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchStrategy {
    /// Fast path: tree-sitter query (pre-compiled S-expression)
    TreeSitterQuery {
        query: String,
        captures: Vec<String>,
    },
    /// Literal string search (fastest for simple cases)
    LiteralSearch {
        literals: Vec<String>,
        case_sensitive: bool,
    },
    /// Pre-validated regex pattern
    Regex { pattern: String },
    /// AST walker for complex patterns (pattern-inside, metavariable-regex)
    AstWalker {
        pattern: String,
        metavariables: Vec<String>,
    },
    /// Taint tracking mode
    Taint {
        sources: Vec<String>,
        sinks: Vec<String>,
        sanitizers: Vec<String>,
    },
    /// Rule was skipped (unsupported pattern)
    Skipped { reason: String },
}

/// Compiled rule format (must match build.rs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRule {
    pub id: String,
    pub message: String,
    pub severity: String,
    pub languages: Vec<String>,
    pub category: Option<String>,
    pub confidence: Option<String>,

    /// Pre-compiled matching strategy
    pub strategy: MatchStrategy,

    /// Additional negative patterns (pattern-not)
    pub pattern_not: Option<String>,

    /// Metadata
    pub cwe: Option<Vec<String>>,
    pub owasp: Option<Vec<String>>,
    pub references: Option<Vec<String>>,
    pub fix: Option<String>,

    /// Optimization: literal strings for fast pre-filtering
    pub literal_triggers: Vec<String>,
}

/// Compiled rules organized by language
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CompiledRuleSet {
    pub by_language: HashMap<String, Vec<CompiledRule>>,
    pub generic: Vec<CompiledRule>,
    pub total_count: usize,
    pub skipped_count: usize,
}

impl CompiledRuleSet {
    /// Get rules for a specific language (includes generic rules)
    pub fn rules_for_language(&self, lang: &str) -> Vec<&CompiledRule> {
        let lang_lower = lang.to_lowercase();
        let mut rules: Vec<&CompiledRule> = Vec::new();

        // Add language-specific rules
        if let Some(lang_rules) = self.by_language.get(&lang_lower) {
            rules.extend(lang_rules.iter());
        }

        // Handle language aliases
        let aliases: &[&str] = match lang_lower.as_str() {
            "javascript" => &["js"],
            "typescript" => &["ts"],
            "python" => &["py"],
            "ruby" => &["rb"],
            _ => &[],
        };

        for alias in aliases {
            if let Some(alias_rules) = self.by_language.get(*alias) {
                rules.extend(alias_rules.iter());
            }
        }

        // Add generic rules
        rules.extend(self.generic.iter());

        rules
    }

    /// Get all active rules (excludes skipped)
    pub fn all_rules(&self) -> impl Iterator<Item = &CompiledRule> {
        self.by_language
            .values()
            .flatten()
            .chain(self.generic.iter())
            .filter(|r| !matches!(r.strategy, MatchStrategy::Skipped { .. }))
    }

    /// Get all rules including skipped
    pub fn all_rules_including_skipped(&self) -> impl Iterator<Item = &CompiledRule> {
        self.by_language
            .values()
            .flatten()
            .chain(self.generic.iter())
    }

    /// Get languages with rules
    pub fn languages(&self) -> Vec<&str> {
        self.by_language.keys().map(|s| s.as_str()).collect()
    }

    /// Get count by strategy type
    pub fn strategy_counts(&self) -> HashMap<&'static str, usize> {
        let mut counts = HashMap::new();
        for rule in self.all_rules_including_skipped() {
            let key = match &rule.strategy {
                MatchStrategy::TreeSitterQuery { .. } => "tree_sitter_query",
                MatchStrategy::LiteralSearch { .. } => "literal_search",
                MatchStrategy::Regex { .. } => "regex",
                MatchStrategy::AstWalker { .. } => "ast_walker",
                MatchStrategy::Taint { .. } => "taint",
                MatchStrategy::Skipped { .. } => "skipped",
            };
            *counts.entry(key).or_insert(0) += 1;
        }
        counts
    }
}

/// Load the embedded ruleset (cached after first call)
pub fn load_embedded_ruleset() -> Result<CompiledRuleSet> {
    // Check if already cached
    {
        let cache = RULESET_CACHE.read().unwrap();
        if let Some(ref ruleset) = *cache {
            return Ok(ruleset.clone());
        }
    }

    // Not cached, deserialize
    debug!(
        "Deserializing embedded rules ({} bytes)",
        COMPILED_RULES.len()
    );

    let ruleset: CompiledRuleSet = bincode::deserialize(COMPILED_RULES)
        .map_err(|e| RuleError::ParseError(format!("Failed to deserialize rules: {}", e)))?;

    let strategy_counts = ruleset.strategy_counts();
    info!(
        "Loaded {} embedded rules ({} skipped) - strategies: {:?}",
        ruleset.total_count, ruleset.skipped_count, strategy_counts
    );

    // Cache it
    {
        let mut cache = RULESET_CACHE.write().unwrap();
        *cache = Some(ruleset.clone());
    }

    Ok(ruleset)
}

/// Load embedded rules and convert to Rule format
pub fn load_embedded_rules() -> Result<Vec<Rule>> {
    let ruleset = load_embedded_ruleset()?;
    Ok(ruleset.all_rules().map(compiled_to_rule).collect())
}

/// Load rules for a specific language
pub fn load_rules_for_language(lang: &str) -> Result<Vec<Rule>> {
    let ruleset = load_embedded_ruleset()?;
    Ok(ruleset
        .rules_for_language(lang)
        .into_iter()
        .filter(|r| !matches!(r.strategy, MatchStrategy::Skipped { .. }))
        .map(compiled_to_rule)
        .collect())
}

/// Get the total count of embedded rules
pub fn embedded_rule_count() -> Result<usize> {
    Ok(load_embedded_ruleset()?.total_count)
}

/// Get statistics about embedded rules
pub fn embedded_stats() -> Result<EmbeddedStats> {
    let ruleset = load_embedded_ruleset()?;

    let mut by_language = HashMap::new();
    for (lang, rules) in &ruleset.by_language {
        by_language.insert(lang.clone(), rules.len());
    }

    let mut by_severity = HashMap::new();
    let mut by_category = HashMap::new();
    let mut taint_count = 0;

    for rule in ruleset.all_rules() {
        *by_severity.entry(rule.severity.clone()).or_insert(0) += 1;

        let cat = rule
            .category
            .clone()
            .unwrap_or_else(|| "uncategorized".to_string());
        *by_category.entry(cat).or_insert(0) += 1;

        if matches!(rule.strategy, MatchStrategy::Taint { .. }) {
            taint_count += 1;
        }
    }

    Ok(EmbeddedStats {
        total: ruleset.total_count,
        skipped: ruleset.skipped_count,
        generic: ruleset.generic.len(),
        by_language,
        by_severity,
        by_category,
        by_strategy: ruleset
            .strategy_counts()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        taint_rules: taint_count,
    })
}

/// Statistics about embedded rules
#[derive(Debug, Clone)]
pub struct EmbeddedStats {
    pub total: usize,
    pub skipped: usize,
    pub generic: usize,
    pub by_language: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
    pub by_category: HashMap<String, usize>,
    pub by_strategy: HashMap<String, usize>,
    pub taint_rules: usize,
}

/// Convert CompiledRule to Rule format
fn compiled_to_rule(compiled: &CompiledRule) -> Rule {
    use crate::format::*;

    type TaintPatterns = Option<Vec<PatternClause>>;

    // Extract pattern based on strategy
    let (pattern, is_taint, sources, sinks, sanitizers): (
        Option<String>,
        bool,
        TaintPatterns,
        TaintPatterns,
        TaintPatterns,
    ) = match &compiled.strategy {
        MatchStrategy::TreeSitterQuery { query, .. } => {
            // Store the tree-sitter query as the pattern
            (Some(query.clone()), false, None, None, None)
        }
        MatchStrategy::LiteralSearch { literals, .. } => {
            // Store first literal as pattern
            (literals.first().cloned(), false, None, None, None)
        }
        MatchStrategy::Regex { pattern } => (Some(pattern.clone()), false, None, None, None),
        MatchStrategy::AstWalker { pattern, .. } => {
            (Some(pattern.clone()), false, None, None, None)
        }
        MatchStrategy::Taint {
            sources,
            sinks,
            sanitizers,
        } => {
            let src = sources
                .iter()
                .map(|p| PatternClause::Simple(p.clone()))
                .collect();
            let snk = sinks
                .iter()
                .map(|p| PatternClause::Simple(p.clone()))
                .collect();
            let san = sanitizers
                .iter()
                .map(|p| PatternClause::Simple(p.clone()))
                .collect();
            (None, true, Some(src), Some(snk), Some(san))
        }
        MatchStrategy::Skipped { .. } => (None, false, None, None, None),
    };

    Rule {
        id: compiled.id.clone(),
        message: compiled.message.clone(),
        severity: match compiled.severity.to_uppercase().as_str() {
            "ERROR" => Severity::Error,
            "WARNING" => Severity::Warning,
            "INFO" => Severity::Info,
            _ => Severity::Warning,
        },
        languages: compiled.languages.clone(),
        mode: if is_taint {
            RuleMode::Taint
        } else {
            RuleMode::Search
        },
        pattern,
        pattern_either: None,
        patterns: None,
        pattern_not: compiled.pattern_not.clone(),
        pattern_regex: None,
        pattern_sources: sources,
        pattern_sinks: sinks,
        pattern_sanitizers: sanitizers,
        pattern_propagators: None,
        metadata: RuleMetadata {
            category: compiled.category.clone(),
            technology: None,
            cwe: compiled.cwe.as_ref().map(|cwes| {
                if cwes.len() == 1 {
                    CweField::Single(cwes[0].clone())
                } else {
                    CweField::Multiple(cwes.clone())
                }
            }),
            owasp: compiled.owasp.clone(),
            confidence: compiled.confidence.as_ref().and_then(|c| {
                match c.to_uppercase().as_str() {
                    "HIGH" => Some(ConfidenceLevel::High),
                    "MEDIUM" => Some(ConfidenceLevel::Medium),
                    "LOW" => Some(ConfidenceLevel::Low),
                    _ => None,
                }
            }),
            impact: None,
            likelihood: None,
            subcategory: None,
            references: compiled.references.clone(),
            source_rule_url: None,
            extra: HashMap::new(),
        },
        fix: compiled.fix.clone(),
        fix_regex: None,
        min_version: None,
        options: None,
    }
}

/// Get literal triggers for a rule (for fast pre-filtering)
pub fn get_literal_triggers(rule_id: &str) -> Option<Vec<String>> {
    let ruleset = load_embedded_ruleset().ok()?;
    for rule in ruleset.all_rules() {
        if rule.id == rule_id {
            return Some(rule.literal_triggers.clone());
        }
    }
    None
}

/// Get the match strategy for a rule
pub fn get_match_strategy(rule_id: &str) -> Option<MatchStrategy> {
    let ruleset = load_embedded_ruleset().ok()?;
    for rule in ruleset.all_rules_including_skipped() {
        if rule.id == rule_id {
            return Some(rule.strategy.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_embedded_rules() {
        let rules = load_embedded_rules();
        // Should succeed even if empty
        assert!(rules.is_ok());
    }

    #[test]
    fn test_embedded_stats() {
        let stats = embedded_stats();
        assert!(stats.is_ok());
        let stats = stats.unwrap();
        // Check that strategy counts are populated
        assert!(!stats.by_strategy.is_empty() || stats.total == 0);
    }

    #[test]
    fn test_rules_for_language() {
        let ruleset = load_embedded_ruleset().unwrap();
        // Generic rules should always be available
        let generic = ruleset.rules_for_language("generic");
        // This includes generic rules at minimum
        assert!(!generic.is_empty() || ruleset.total_count == 0);
    }

    #[test]
    fn test_strategy_counts() {
        let ruleset = load_embedded_ruleset().unwrap();
        let counts = ruleset.strategy_counts();
        // Should have at least some strategies
        let total: usize = counts.values().sum();
        assert!(total > 0 || ruleset.total_count == 0);
    }
}
