//! Rule format definitions - Semgrep-compatible YAML structure
//!
//! This module defines the data structures for parsing Semgrep rules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Root structure of a rule file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    pub rules: Vec<Rule>,
}

/// A single rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier
    pub id: String,

    /// Human-readable message explaining the finding
    pub message: String,

    /// Severity level
    pub severity: Severity,

    /// Languages this rule applies to
    pub languages: Vec<String>,

    /// Rule mode (search, taint, join, extract)
    #[serde(default)]
    pub mode: RuleMode,

    // Pattern matching options (mutually exclusive in some cases)
    /// Simple pattern match
    #[serde(default)]
    pub pattern: Option<String>,

    /// Multiple patterns where any can match
    #[serde(default, rename = "pattern-either")]
    pub pattern_either: Option<Vec<PatternClause>>,

    /// All patterns must match
    #[serde(default)]
    pub patterns: Option<Vec<PatternClause>>,

    /// Pattern that must NOT match
    #[serde(default, rename = "pattern-not")]
    pub pattern_not: Option<String>,

    /// Regex pattern
    #[serde(default, rename = "pattern-regex")]
    pub pattern_regex: Option<String>,

    // Taint mode specific
    /// Taint sources
    #[serde(default, rename = "pattern-sources")]
    pub pattern_sources: Option<Vec<PatternClause>>,

    /// Taint sinks
    #[serde(default, rename = "pattern-sinks")]
    pub pattern_sinks: Option<Vec<PatternClause>>,

    /// Taint sanitizers
    #[serde(default, rename = "pattern-sanitizers")]
    pub pattern_sanitizers: Option<Vec<PatternClause>>,

    /// Taint propagators
    #[serde(default, rename = "pattern-propagators")]
    pub pattern_propagators: Option<Vec<PatternClause>>,

    /// Rule metadata
    #[serde(default)]
    pub metadata: RuleMetadata,

    /// Fix suggestion
    #[serde(default)]
    pub fix: Option<String>,

    /// Fix regex replacement
    #[serde(default, rename = "fix-regex")]
    pub fix_regex: Option<FixRegex>,

    /// Minimum semgrep version
    #[serde(default, rename = "min-version")]
    pub min_version: Option<String>,

    /// Rule options
    #[serde(default)]
    pub options: Option<RuleOptions>,
}

/// Severity levels (Semgrep compatible)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Error,
    #[default]
    Warning,
    Info,
    Inventory,
    Experiment,
}

impl From<Severity> for rma_common::Severity {
    fn from(s: Severity) -> Self {
        match s {
            Severity::Error => rma_common::Severity::Error,
            Severity::Warning => rma_common::Severity::Warning,
            Severity::Info => rma_common::Severity::Info,
            Severity::Inventory => rma_common::Severity::Info,
            Severity::Experiment => rma_common::Severity::Info,
        }
    }
}

/// Rule mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    #[default]
    Search,
    Taint,
    Join,
    Extract,
}

/// Pattern clause - can be a simple pattern or complex nested structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PatternClause {
    /// Simple string pattern
    Simple(String),

    /// Complex pattern with operators
    Complex(PatternOperator),
}

/// Pattern operators for complex matching
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PatternOperator {
    /// Simple pattern
    #[serde(default)]
    pub pattern: Option<String>,

    /// Pattern either (OR)
    #[serde(default, rename = "pattern-either")]
    pub pattern_either: Option<Vec<PatternClause>>,

    /// Patterns (AND)
    #[serde(default)]
    pub patterns: Option<Vec<PatternClause>>,

    /// Pattern not
    #[serde(default, rename = "pattern-not")]
    pub pattern_not: Option<String>,

    /// Pattern inside - match must be inside this
    #[serde(default, rename = "pattern-inside")]
    pub pattern_inside: Option<String>,

    /// Pattern not inside
    #[serde(default, rename = "pattern-not-inside")]
    pub pattern_not_inside: Option<String>,

    /// Pattern regex
    #[serde(default, rename = "pattern-regex")]
    pub pattern_regex: Option<String>,

    /// Pattern not regex
    #[serde(default, rename = "pattern-not-regex")]
    pub pattern_not_regex: Option<String>,

    /// Focus on a metavariable
    #[serde(default, rename = "focus-metavariable")]
    pub focus_metavariable: Option<String>,

    /// Metavariable regex constraint
    #[serde(default, rename = "metavariable-regex")]
    pub metavariable_regex: Option<MetavariableRegex>,

    /// Metavariable pattern constraint
    #[serde(default, rename = "metavariable-pattern")]
    pub metavariable_pattern: Option<MetavariablePattern>,

    /// Metavariable comparison
    #[serde(default, rename = "metavariable-comparison")]
    pub metavariable_comparison: Option<MetavariableComparison>,

    /// By side effect (for taint sources)
    #[serde(default, rename = "by-side-effect")]
    pub by_side_effect: Option<bool>,
}

/// Metavariable regex constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetavariableRegex {
    pub metavariable: String,
    pub regex: String,
}

/// Metavariable pattern constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetavariablePattern {
    pub metavariable: String,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub patterns: Option<Vec<PatternClause>>,
    #[serde(default, rename = "pattern-either")]
    pub pattern_either: Option<Vec<PatternClause>>,
}

/// Metavariable comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetavariableComparison {
    pub metavariable: String,
    pub comparison: String,
    #[serde(default)]
    pub base: Option<i32>,
    #[serde(default)]
    pub strip: Option<bool>,
}

/// Rule metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// Security category
    #[serde(default)]
    pub category: Option<String>,

    /// Technology/framework
    #[serde(default)]
    pub technology: Option<Vec<String>>,

    /// CWE identifiers
    #[serde(default)]
    pub cwe: Option<CweField>,

    /// OWASP categories
    #[serde(default)]
    pub owasp: Option<Vec<String>>,

    /// Confidence level
    #[serde(default)]
    pub confidence: Option<ConfidenceLevel>,

    /// Impact level
    #[serde(default)]
    pub impact: Option<ImpactLevel>,

    /// Likelihood level
    #[serde(default)]
    pub likelihood: Option<LikelihoodLevel>,

    /// Subcategory
    #[serde(default)]
    pub subcategory: Option<Vec<String>>,

    /// References
    #[serde(default)]
    pub references: Option<Vec<String>>,

    /// Source rule URL
    #[serde(default, rename = "source-rule-url")]
    pub source_rule_url: Option<String>,

    /// Additional fields we don't explicitly handle
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

/// CWE field can be a string or list of strings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CweField {
    Single(String),
    Multiple(Vec<String>),
}

impl CweField {
    pub fn as_vec(&self) -> Vec<&str> {
        match self {
            CweField::Single(s) => vec![s.as_str()],
            CweField::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

/// Confidence levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum ConfidenceLevel {
    High,
    #[default]
    Medium,
    Low,
}

impl From<ConfidenceLevel> for rma_common::Confidence {
    fn from(c: ConfidenceLevel) -> Self {
        match c {
            ConfidenceLevel::High => rma_common::Confidence::High,
            ConfidenceLevel::Medium => rma_common::Confidence::Medium,
            ConfidenceLevel::Low => rma_common::Confidence::Low,
        }
    }
}

/// Impact levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum ImpactLevel {
    High,
    #[default]
    Medium,
    Low,
}

/// Likelihood levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum LikelihoodLevel {
    High,
    #[default]
    Medium,
    Low,
}

/// Fix regex replacement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixRegex {
    pub regex: String,
    pub replacement: String,
    #[serde(default)]
    pub count: Option<i32>,
}

/// Rule options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleOptions {
    /// Symbolic propagation
    #[serde(default)]
    pub symbolic_propagation: Option<bool>,

    /// Constant propagation
    #[serde(default)]
    pub constant_propagation: Option<bool>,

    /// Taint mode options
    #[serde(default)]
    pub taint_assume_safe_numbers: Option<bool>,

    #[serde(default)]
    pub taint_assume_safe_booleans: Option<bool>,

    /// Additional options
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

impl Rule {
    /// Check if this is a taint-mode rule
    pub fn is_taint_mode(&self) -> bool {
        self.mode == RuleMode::Taint
            || self.pattern_sources.is_some()
            || self.pattern_sinks.is_some()
    }

    /// Get the category from metadata
    pub fn category(&self) -> &str {
        self.metadata.category.as_deref().unwrap_or("security")
    }

    /// Get confidence level
    pub fn confidence(&self) -> rma_common::Confidence {
        self.metadata
            .confidence
            .map(|c| c.into())
            .unwrap_or(rma_common::Confidence::Medium)
    }

    /// Check if rule applies to a language
    pub fn applies_to(&self, lang: &str) -> bool {
        let lang_lower = lang.to_lowercase();
        self.languages.iter().any(|l| {
            let l_lower = l.to_lowercase();
            l_lower == lang_lower
                || (l_lower == "js" && lang_lower == "javascript")
                || (l_lower == "javascript" && lang_lower == "js")
                || (l_lower == "ts" && lang_lower == "typescript")
                || (l_lower == "typescript" && lang_lower == "ts")
                || (l_lower == "py" && lang_lower == "python")
                || (l_lower == "python" && lang_lower == "py")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let yaml = r#"
rules:
  - id: test-rule
    pattern: dangerous_func($X)
    message: Avoid dangerous function
    severity: ERROR
    languages: [python, javascript]
"#;
        let file: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(file.rules.len(), 1);
        assert_eq!(file.rules[0].id, "test-rule");
        assert_eq!(
            file.rules[0].pattern,
            Some("dangerous_func($X)".to_string())
        );
        assert_eq!(file.rules[0].severity, Severity::Error);
    }

    #[test]
    fn test_parse_taint_rule() {
        let yaml = r#"
rules:
  - id: sql-injection
    mode: taint
    message: SQL injection
    severity: ERROR
    languages: [python]
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sinks:
      - pattern: cursor.execute($QUERY, ...)
    pattern-sanitizers:
      - pattern: escape($X)
"#;
        let file: RuleFile = serde_yaml::from_str(yaml).unwrap();
        assert!(file.rules[0].is_taint_mode());
        assert!(file.rules[0].pattern_sources.is_some());
        assert!(file.rules[0].pattern_sinks.is_some());
    }

    #[test]
    fn test_rule_applies_to_language() {
        let rule = Rule {
            id: "test".to_string(),
            message: "test".to_string(),
            severity: Severity::Warning,
            languages: vec!["python".to_string(), "js".to_string()],
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
            metadata: RuleMetadata::default(),
            fix: None,
            fix_regex: None,
            min_version: None,
            options: None,
        };

        assert!(rule.applies_to("python"));
        assert!(rule.applies_to("Python"));
        assert!(rule.applies_to("js"));
        assert!(rule.applies_to("javascript"));
        assert!(!rule.applies_to("rust"));
    }
}
