//! Rule loader - loads rules from YAML files and directories

use crate::{format::RuleFile, Result, Rule, RuleError};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

/// Load rules from a single YAML file
pub fn load_rule_file(path: &Path) -> Result<Vec<Rule>> {
    let content = std::fs::read_to_string(path)?;
    let rule_file: RuleFile = serde_yaml::from_str(&content)
        .map_err(|e| RuleError::ParseError(format!("{}: {}", path.display(), e)))?;
    Ok(rule_file.rules)
}

/// Load all rules from a directory recursively
pub fn load_rules_from_dir(dir: &Path) -> Result<Vec<Rule>> {
    let yaml_files: Vec<PathBuf> = WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    info!(
        "Found {} YAML rule files in {}",
        yaml_files.len(),
        dir.display()
    );

    // Load rules in parallel
    let results: Vec<Result<Vec<Rule>>> = yaml_files
        .par_iter()
        .map(|path| {
            match load_rule_file(path) {
                Ok(rules) => {
                    debug!("Loaded {} rules from {}", rules.len(), path.display());
                    Ok(rules)
                }
                Err(e) => {
                    warn!("Failed to load {}: {}", path.display(), e);
                    // Return empty vec instead of failing completely
                    Ok(vec![])
                }
            }
        })
        .collect();

    // Flatten all rules
    let mut all_rules = Vec::new();
    for result in results {
        all_rules.extend(result?);
    }

    info!("Loaded {} total rules", all_rules.len());
    Ok(all_rules)
}

/// Load rules from multiple directories
pub fn load_rules_from_dirs(dirs: &[&Path]) -> Result<Vec<Rule>> {
    let mut all_rules = Vec::new();
    for dir in dirs {
        if dir.exists() {
            all_rules.extend(load_rules_from_dir(dir)?);
        } else {
            warn!("Rule directory does not exist: {}", dir.display());
        }
    }
    Ok(all_rules)
}

/// Load rules for specific languages only
pub fn load_rules_for_languages(dir: &Path, languages: &[&str]) -> Result<Vec<Rule>> {
    let all_rules = load_rules_from_dir(dir)?;

    let filtered: Vec<Rule> = all_rules
        .into_iter()
        .filter(|rule| languages.iter().any(|lang| rule.applies_to(lang)))
        .collect();

    info!(
        "Filtered to {} rules for languages: {:?}",
        filtered.len(),
        languages
    );
    Ok(filtered)
}

/// Rule loader configuration
#[derive(Debug, Clone)]
pub struct RuleLoaderConfig {
    /// Directories to load rules from
    pub rule_dirs: Vec<PathBuf>,

    /// Languages to filter for (empty = all)
    pub languages: Vec<String>,

    /// Categories to include (empty = all)
    pub categories: Vec<String>,

    /// Minimum severity to include
    pub min_severity: Option<crate::format::Severity>,

    /// Whether to include taint rules
    pub include_taint: bool,
}

impl Default for RuleLoaderConfig {
    fn default() -> Self {
        Self {
            rule_dirs: vec![],
            languages: vec![],
            categories: vec![],
            min_severity: None,
            include_taint: true,
        }
    }
}

impl RuleLoaderConfig {
    /// Create a new config with default semgrep-rules directory
    pub fn with_semgrep_rules(semgrep_dir: PathBuf) -> Self {
        Self {
            rule_dirs: vec![semgrep_dir],
            ..Default::default()
        }
    }

    /// Add a rule directory
    pub fn add_dir(mut self, dir: PathBuf) -> Self {
        self.rule_dirs.push(dir);
        self
    }

    /// Filter to specific languages
    pub fn for_languages(mut self, languages: Vec<String>) -> Self {
        self.languages = languages;
        self
    }

    /// Filter to specific categories
    pub fn for_categories(mut self, categories: Vec<String>) -> Self {
        self.categories = categories;
        self
    }

    /// Set minimum severity
    pub fn min_severity(mut self, severity: crate::format::Severity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// Load rules with this configuration
    pub fn load(&self) -> Result<Vec<Rule>> {
        let mut all_rules = Vec::new();

        for dir in &self.rule_dirs {
            if dir.exists() {
                all_rules.extend(load_rules_from_dir(dir)?);
            }
        }

        // Apply filters
        let filtered: Vec<Rule> = all_rules
            .into_iter()
            .filter(|rule| {
                // Language filter
                if !self.languages.is_empty() && !self.languages.iter().any(|l| rule.applies_to(l))
                {
                    return false;
                }

                // Category filter
                if !self.categories.is_empty()
                    && !self.categories.iter().any(|c| rule.category() == c)
                {
                    return false;
                }

                // Severity filter
                if let Some(min_sev) = self.min_severity {
                    let rule_sev = rule.severity;
                    // Error > Warning > Info
                    let passes = match min_sev {
                        crate::format::Severity::Error => {
                            rule_sev == crate::format::Severity::Error
                        }
                        crate::format::Severity::Warning => {
                            rule_sev == crate::format::Severity::Error
                                || rule_sev == crate::format::Severity::Warning
                        }
                        _ => true,
                    };
                    if !passes {
                        return false;
                    }
                }

                // Taint filter
                if !self.include_taint && rule.is_taint_mode() {
                    return false;
                }

                true
            })
            .collect();

        Ok(filtered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_rule_file(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn test_load_single_rule_file() {
        let dir = TempDir::new().unwrap();
        create_test_rule_file(
            dir.path(),
            "test.yaml",
            r#"
rules:
  - id: test-rule
    pattern: dangerous($X)
    message: Test message
    severity: WARNING
    languages: [python]
"#,
        );

        let rules = load_rule_file(&dir.path().join("test.yaml")).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "test-rule");
    }

    #[test]
    fn test_load_rules_from_dir() {
        let dir = TempDir::new().unwrap();

        // Create subdirectory
        std::fs::create_dir(dir.path().join("subdir")).unwrap();

        create_test_rule_file(
            dir.path(),
            "rule1.yaml",
            r#"
rules:
  - id: rule1
    pattern: func1($X)
    message: Rule 1
    severity: ERROR
    languages: [python]
"#,
        );

        create_test_rule_file(
            &dir.path().join("subdir"),
            "rule2.yaml",
            r#"
rules:
  - id: rule2
    pattern: func2($X)
    message: Rule 2
    severity: WARNING
    languages: [javascript]
"#,
        );

        let rules = load_rules_from_dir(dir.path()).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_filter_by_language() {
        let dir = TempDir::new().unwrap();
        create_test_rule_file(
            dir.path(),
            "rules.yaml",
            r#"
rules:
  - id: python-rule
    pattern: py_func($X)
    message: Python rule
    severity: WARNING
    languages: [python]
  - id: js-rule
    pattern: js_func($X)
    message: JS rule
    severity: WARNING
    languages: [javascript]
"#,
        );

        let rules = load_rules_for_languages(dir.path(), &["python"]).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "python-rule");
    }
}
