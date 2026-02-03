//! Rule translator - converts between rule formats
//!
//! This module handles:
//! - Loading Semgrep rules directly (they're already in our format)
//! - Converting from other formats if needed
//! - Validating and normalizing rules

use crate::{Result, Rule, RuleError, RuleFile};
use std::path::Path;
use tracing::{debug, warn};

/// Translate/load a rule file
pub fn load_and_translate(path: &Path) -> Result<Vec<Rule>> {
    let content = std::fs::read_to_string(path)?;

    // Try to parse as Semgrep format first
    match serde_yaml::from_str::<RuleFile>(&content) {
        Ok(file) => {
            let rules: Vec<Rule> = file
                .rules
                .into_iter()
                .filter_map(|r| validate_and_normalize(r, path))
                .collect();
            Ok(rules)
        }
        Err(e) => {
            // Try alternate formats or return error
            debug!(
                "Failed to parse {} as Semgrep format: {}",
                path.display(),
                e
            );
            Err(RuleError::ParseError(format!(
                "Failed to parse {}: {}",
                path.display(),
                e
            )))
        }
    }
}

/// Validate and normalize a rule
fn validate_and_normalize(mut rule: Rule, source: &Path) -> Option<Rule> {
    // Must have an ID
    if rule.id.is_empty() {
        warn!("Rule in {} has no ID, skipping", source.display());
        return None;
    }

    // Must have at least one pattern
    if !has_any_pattern(&rule) {
        warn!("Rule {} has no patterns, skipping", rule.id);
        return None;
    }

    // Must have at least one language
    if rule.languages.is_empty() {
        warn!("Rule {} has no languages, skipping", rule.id);
        return None;
    }

    // Normalize language names
    rule.languages = rule.languages.into_iter().map(normalize_language).collect();

    // Add source info if not present
    if rule.metadata.source_rule_url.is_none() {
        rule.metadata.source_rule_url = Some(format!("file://{}", source.display()));
    }

    Some(rule)
}

/// Check if a rule has any pattern defined
fn has_any_pattern(rule: &Rule) -> bool {
    rule.pattern.is_some()
        || rule.pattern_either.is_some()
        || rule.patterns.is_some()
        || rule.pattern_regex.is_some()
        || rule.pattern_sources.is_some()
        || rule.pattern_sinks.is_some()
}

/// Normalize language name
fn normalize_language(lang: String) -> String {
    match lang.to_lowercase().as_str() {
        "js" => "javascript".to_string(),
        "ts" => "typescript".to_string(),
        "py" => "python".to_string(),
        "rb" => "ruby".to_string(),
        "rs" => "rust".to_string(),
        "yml" => "yaml".to_string(),
        other => other.to_string(),
    }
}

/// Statistics about rule translation
#[derive(Debug, Clone, Default)]
pub struct TranslationStats {
    pub files_processed: usize,
    pub rules_loaded: usize,
    pub rules_skipped: usize,
    pub errors: Vec<String>,
}

/// Batch translate rules from a directory
pub fn translate_directory(dir: &Path) -> Result<(Vec<Rule>, TranslationStats)> {
    use walkdir::WalkDir;

    let mut all_rules = Vec::new();
    let mut stats = TranslationStats::default();

    for entry in WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();

        if !path
            .extension()
            .map(|e| e == "yaml" || e == "yml")
            .unwrap_or(false)
        {
            continue;
        }

        stats.files_processed += 1;

        match load_and_translate(path) {
            Ok(rules) => {
                stats.rules_loaded += rules.len();
                all_rules.extend(rules);
            }
            Err(e) => {
                stats.errors.push(format!("{}: {}", path.display(), e));
            }
        }
    }

    Ok((all_rules, stats))
}

/// Convert RMA's internal rule format to Semgrep YAML for export
pub fn rule_to_yaml(rule: &Rule) -> Result<String> {
    let file = RuleFile {
        rules: vec![rule.clone()],
    };
    serde_yaml::to_string(&file).map_err(|e| RuleError::ParseError(e.to_string()))
}

/// Export multiple rules to YAML
pub fn rules_to_yaml(rules: &[Rule]) -> Result<String> {
    let file = RuleFile {
        rules: rules.to_vec(),
    };
    serde_yaml::to_string(&file).map_err(|e| RuleError::ParseError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_normalize_language() {
        assert_eq!(normalize_language("js".to_string()), "javascript");
        assert_eq!(normalize_language("JS".to_string()), "javascript");
        assert_eq!(normalize_language("python".to_string()), "python");
        assert_eq!(normalize_language("ts".to_string()), "typescript");
    }

    #[test]
    fn test_load_and_translate() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.yaml");

        let content = r#"
rules:
  - id: test-rule
    pattern: print($X)
    message: Test message
    severity: WARNING
    languages: [py]
"#;
        std::fs::File::create(&path)
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();

        let rules = load_and_translate(&path).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test-rule");
        // Language should be normalized
        assert!(rules[0].languages.contains(&"python".to_string()));
    }

    #[test]
    fn test_rule_to_yaml() {
        use crate::format::{RuleMetadata, RuleMode, Severity};

        let rule = Rule {
            id: "test".to_string(),
            message: "Test message".to_string(),
            severity: Severity::Warning,
            languages: vec!["python".to_string()],
            mode: RuleMode::Search,
            pattern: Some("test($X)".to_string()),
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

        let yaml = rule_to_yaml(&rule).unwrap();
        assert!(yaml.contains("id: test"));
        assert!(yaml.contains("pattern: test($X)"));
    }
}
