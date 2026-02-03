//! Finding filter system for the CLI
//!
//! Provides comprehensive filtering capabilities for scan results including:
//! - Severity filtering
//! - Rule ID filtering (include/exclude)
//! - File pattern filtering (glob-based include/exclude)
//! - Category filtering
//! - Fixable-only filtering
//! - High-confidence filtering
//! - Text/regex search
//! - Smart presets (security, ci, review)
//! - Saved filter profiles from config

use glob::Pattern;
use regex::Regex;
use rma_common::{Confidence, Finding, FindingCategory, Severity};
use std::collections::HashSet;
use std::path::Path;

/// Statistics about filtered findings for the explain feature
#[derive(Debug, Clone, Default)]
pub struct FilterStats {
    /// Total findings before filtering
    pub total_before: usize,
    /// Total findings after filtering
    pub total_after: usize,
    /// Findings filtered by severity
    pub by_severity: usize,
    /// Findings filtered by included rules (not matching)
    pub by_rules_include: usize,
    /// Findings filtered by excluded rules
    pub by_rules_exclude: usize,
    /// Findings filtered by included files (not matching)
    pub by_files_include: usize,
    /// Findings filtered by excluded files
    pub by_files_exclude: usize,
    /// Findings filtered by category
    pub by_category: usize,
    /// Findings filtered by fixable requirement
    pub by_fixable: usize,
    /// Findings filtered by high-confidence requirement
    pub by_confidence: usize,
    /// Findings filtered by search text
    pub by_search: usize,
    /// Breakdown of excluded severities (severity -> count)
    pub severity_breakdown: Vec<(Severity, usize)>,
    /// Breakdown of excluded rules (rule_id -> count)
    pub excluded_rules_breakdown: Vec<(String, usize)>,
    /// Breakdown of excluded files (pattern matched -> count)
    pub excluded_files_breakdown: Vec<(String, usize)>,
}

impl FilterStats {
    /// Check if any findings were filtered
    pub fn has_filtered(&self) -> bool {
        self.total_before > self.total_after
    }

    /// Get total filtered count
    pub fn filtered_count(&self) -> usize {
        self.total_before.saturating_sub(self.total_after)
    }
}

/// Severity level for filtering (with ValueEnum support)
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SeverityFilter {
    Critical,
    Error,
    Warning,
    Info,
}

impl From<SeverityFilter> for Severity {
    fn from(sf: SeverityFilter) -> Self {
        match sf {
            SeverityFilter::Critical => Severity::Critical,
            SeverityFilter::Error => Severity::Error,
            SeverityFilter::Warning => Severity::Warning,
            SeverityFilter::Info => Severity::Info,
        }
    }
}

/// Category filter with ValueEnum support
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CategoryFilter {
    Security,
    Quality,
    Performance,
    Style,
}

impl From<CategoryFilter> for FindingCategory {
    fn from(cf: CategoryFilter) -> Self {
        match cf {
            CategoryFilter::Security => FindingCategory::Security,
            CategoryFilter::Quality => FindingCategory::Quality,
            CategoryFilter::Performance => FindingCategory::Performance,
            CategoryFilter::Style => FindingCategory::Style,
        }
    }
}

/// A filter profile loaded from configuration
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct FilterProfile {
    /// Profile name
    #[serde(skip)]
    pub name: String,
    /// Minimum severity
    #[serde(default)]
    pub severity: Option<String>,
    /// Rules to include (supports glob patterns)
    #[serde(default)]
    pub rules: Vec<String>,
    /// Rules to exclude
    #[serde(default)]
    pub exclude_rules: Vec<String>,
    /// File patterns to include
    #[serde(default)]
    pub files: Vec<String>,
    /// File patterns to exclude
    #[serde(default)]
    pub exclude_files: Vec<String>,
    /// Category filter
    #[serde(default)]
    pub category: Option<String>,
    /// Only fixable findings
    #[serde(default)]
    pub fixable: bool,
    /// Only high-confidence findings
    #[serde(default)]
    pub high_confidence: bool,
    /// Output format override
    #[serde(default)]
    pub format: Option<String>,
}

/// Comprehensive finding filter
#[derive(Debug, Clone, Default)]
pub struct FindingFilter {
    /// Minimum severity threshold
    pub min_severity: Option<Severity>,
    /// Rules to include (empty = all, supports glob patterns)
    pub rules: HashSet<String>,
    /// Rule patterns to include (compiled from glob patterns in rules)
    rules_patterns: Vec<Pattern>,
    /// Rules to exclude
    pub exclude_rules: HashSet<String>,
    /// Exclude rule patterns (compiled from glob patterns)
    exclude_rules_patterns: Vec<Pattern>,
    /// File patterns to include (empty = all)
    pub file_patterns: Vec<Pattern>,
    /// File patterns to exclude
    pub exclude_patterns: Vec<Pattern>,
    /// Category filter
    pub category: Option<FindingCategory>,
    /// Only show fixable findings
    pub fixable_only: bool,
    /// Only show high-confidence findings
    pub high_confidence_only: bool,
    /// Text search (case-insensitive substring)
    pub search_text: Option<String>,
    /// Regex search (takes precedence over text search)
    pub search_regex: Option<Regex>,
    /// Track statistics for explain mode
    track_stats: bool,
    /// Collected statistics (only when track_stats is true)
    #[allow(dead_code)] // Used for explain mode statistics tracking
    stats: FilterStats,
}

impl FindingFilter {
    /// Create a new empty filter (matches everything)
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable statistics tracking for explain mode
    pub fn with_stats(mut self) -> Self {
        self.track_stats = true;
        self
    }

    /// Set minimum severity threshold
    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// Add rules to include (supports glob patterns like "security/*")
    pub fn with_rules(mut self, rules: Vec<String>) -> Self {
        for rule in rules {
            if rule.contains('*') || rule.contains('?') {
                if let Ok(pattern) = Pattern::new(&rule) {
                    self.rules_patterns.push(pattern);
                }
            } else {
                self.rules.insert(rule);
            }
        }
        self
    }

    /// Add rules to exclude
    pub fn with_exclude_rules(mut self, rules: Vec<String>) -> Self {
        for rule in rules {
            if rule.contains('*') || rule.contains('?') {
                if let Ok(pattern) = Pattern::new(&rule) {
                    self.exclude_rules_patterns.push(pattern);
                }
            } else {
                self.exclude_rules.insert(rule);
            }
        }
        self
    }

    /// Add file patterns to include
    pub fn with_files(mut self, patterns: Vec<String>) -> Self {
        for pattern in patterns {
            if let Ok(p) = Pattern::new(&pattern) {
                self.file_patterns.push(p);
            }
        }
        self
    }

    /// Add file patterns to exclude
    pub fn with_exclude_files(mut self, patterns: Vec<String>) -> Self {
        for pattern in patterns {
            if let Ok(p) = Pattern::new(&pattern) {
                self.exclude_patterns.push(p);
            }
        }
        self
    }

    /// Set category filter
    pub fn with_category(mut self, category: FindingCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Only show fixable findings
    pub fn with_fixable_only(mut self, fixable: bool) -> Self {
        self.fixable_only = fixable;
        self
    }

    /// Only show high-confidence findings
    pub fn with_high_confidence_only(mut self, high: bool) -> Self {
        self.high_confidence_only = high;
        self
    }

    /// Set text search (case-insensitive)
    pub fn with_search(mut self, text: String) -> Self {
        self.search_text = Some(text.to_lowercase());
        self
    }

    /// Set regex search
    pub fn with_search_regex(mut self, pattern: &str) -> anyhow::Result<Self> {
        self.search_regex = Some(Regex::new(pattern)?);
        Ok(self)
    }

    /// Create a security-focused preset
    pub fn preset_security() -> Self {
        Self::new()
            .with_category(FindingCategory::Security)
            .with_high_confidence_only(true)
            .with_min_severity(Severity::Warning)
    }

    /// Create a CI-optimized preset
    pub fn preset_ci() -> Self {
        Self::new().with_min_severity(Severity::Error)
    }

    /// Create a review-focused preset
    pub fn preset_review() -> Self {
        Self::new().with_min_severity(Severity::Warning)
    }

    /// Load filter from a profile
    pub fn from_profile(profile: &FilterProfile) -> anyhow::Result<Self> {
        let mut filter = Self::new();

        // Parse severity
        if let Some(ref sev) = profile.severity {
            let severity = match sev.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "error" | "high" => Severity::Error,
                "warning" | "medium" => Severity::Warning,
                "info" | "low" => Severity::Info,
                _ => Severity::Warning,
            };
            filter = filter.with_min_severity(severity);
        }

        // Parse rules
        if !profile.rules.is_empty() {
            filter = filter.with_rules(profile.rules.clone());
        }

        if !profile.exclude_rules.is_empty() {
            filter = filter.with_exclude_rules(profile.exclude_rules.clone());
        }

        // Parse file patterns
        if !profile.files.is_empty() {
            filter = filter.with_files(profile.files.clone());
        }

        if !profile.exclude_files.is_empty() {
            filter = filter.with_exclude_files(profile.exclude_files.clone());
        }

        // Parse category
        if let Some(ref cat) = profile.category {
            let category = match cat.to_lowercase().as_str() {
                "security" => FindingCategory::Security,
                "quality" => FindingCategory::Quality,
                "performance" => FindingCategory::Performance,
                "style" => FindingCategory::Style,
                _ => FindingCategory::Security,
            };
            filter = filter.with_category(category);
        }

        filter.fixable_only = profile.fixable;
        filter.high_confidence_only = profile.high_confidence;

        Ok(filter)
    }

    /// Check if a finding matches the filter
    #[allow(dead_code)] // Public API for filtering findings
    pub fn matches(&self, finding: &Finding) -> bool {
        // Severity check
        if let Some(min_sev) = self.min_severity {
            if finding.severity < min_sev {
                return false;
            }
        }

        // Rule inclusion check
        if !self.rules.is_empty() || !self.rules_patterns.is_empty() {
            let rule_matched = self.rules.contains(&finding.rule_id)
                || self
                    .rules_patterns
                    .iter()
                    .any(|p| p.matches(&finding.rule_id));
            if !rule_matched {
                return false;
            }
        }

        // Rule exclusion check
        if self.exclude_rules.contains(&finding.rule_id) {
            return false;
        }
        if self
            .exclude_rules_patterns
            .iter()
            .any(|p| p.matches(&finding.rule_id))
        {
            return false;
        }

        // File inclusion check
        let file_path = finding.location.file.to_string_lossy();
        if !self.file_patterns.is_empty() {
            let file_matched = self.file_patterns.iter().any(|p| p.matches(&file_path));
            if !file_matched {
                return false;
            }
        }

        // File exclusion check
        if self.exclude_patterns.iter().any(|p| p.matches(&file_path)) {
            return false;
        }

        // Category check
        if let Some(cat) = self.category {
            if finding.category != cat {
                return false;
            }
        }

        // Fixable check
        if self.fixable_only && finding.fix.is_none() && finding.suggestion.is_none() {
            return false;
        }

        // High confidence check
        if self.high_confidence_only && finding.confidence != Confidence::High {
            return false;
        }

        // Search check
        if let Some(ref regex) = self.search_regex {
            if !regex.is_match(&finding.message) && !regex.is_match(&finding.rule_id) {
                return false;
            }
        } else if let Some(ref text) = self.search_text {
            let message_lower = finding.message.to_lowercase();
            let rule_lower = finding.rule_id.to_lowercase();
            if !message_lower.contains(text) && !rule_lower.contains(text) {
                return false;
            }
        }

        true
    }

    /// Check if a finding matches and track stats (for explain mode)
    fn matches_with_tracking(&mut self, finding: &Finding) -> (bool, Option<FilterReason>) {
        // Severity check
        if let Some(min_sev) = self.min_severity {
            if finding.severity < min_sev {
                return (false, Some(FilterReason::Severity(finding.severity)));
            }
        }

        // Rule inclusion check
        if !self.rules.is_empty() || !self.rules_patterns.is_empty() {
            let rule_matched = self.rules.contains(&finding.rule_id)
                || self
                    .rules_patterns
                    .iter()
                    .any(|p| p.matches(&finding.rule_id));
            if !rule_matched {
                return (
                    false,
                    Some(FilterReason::RuleNotIncluded(finding.rule_id.clone())),
                );
            }
        }

        // Rule exclusion check
        if self.exclude_rules.contains(&finding.rule_id) {
            return (
                false,
                Some(FilterReason::RuleExcluded(finding.rule_id.clone())),
            );
        }
        if self
            .exclude_rules_patterns
            .iter()
            .any(|p| p.matches(&finding.rule_id))
        {
            return (
                false,
                Some(FilterReason::RuleExcluded(finding.rule_id.clone())),
            );
        }

        // File inclusion check
        let file_path = finding.location.file.to_string_lossy().to_string();
        if !self.file_patterns.is_empty() {
            let file_matched = self.file_patterns.iter().any(|p| p.matches(&file_path));
            if !file_matched {
                return (false, Some(FilterReason::FileNotIncluded(file_path)));
            }
        }

        // File exclusion check
        for pattern in &self.exclude_patterns {
            if pattern.matches(&file_path) {
                return (false, Some(FilterReason::FileExcluded(pattern.to_string())));
            }
        }

        // Category check
        if let Some(cat) = self.category {
            if finding.category != cat {
                return (false, Some(FilterReason::Category(finding.category)));
            }
        }

        // Fixable check
        if self.fixable_only && finding.fix.is_none() && finding.suggestion.is_none() {
            return (false, Some(FilterReason::NotFixable));
        }

        // High confidence check
        if self.high_confidence_only && finding.confidence != Confidence::High {
            return (false, Some(FilterReason::LowConfidence(finding.confidence)));
        }

        // Search check
        if let Some(ref regex) = self.search_regex {
            if !regex.is_match(&finding.message) && !regex.is_match(&finding.rule_id) {
                return (false, Some(FilterReason::SearchNoMatch));
            }
        } else if let Some(ref text) = self.search_text {
            let message_lower = finding.message.to_lowercase();
            let rule_lower = finding.rule_id.to_lowercase();
            if !message_lower.contains(text) && !rule_lower.contains(text) {
                return (false, Some(FilterReason::SearchNoMatch));
            }
        }

        (true, None)
    }

    /// Apply filter to a list of findings, returning filtered list
    #[allow(dead_code)] // Public API for filtering findings
    pub fn apply(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings.into_iter().filter(|f| self.matches(f)).collect()
    }

    /// Apply filter with statistics tracking for explain mode
    pub fn apply_with_stats(&mut self, findings: Vec<Finding>) -> (Vec<Finding>, FilterStats) {
        let total_before = findings.len();
        let mut severity_counts: std::collections::HashMap<Severity, usize> =
            std::collections::HashMap::new();
        let mut excluded_rules: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut excluded_files: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();

        let mut stats = FilterStats {
            total_before,
            ..Default::default()
        };

        let result: Vec<Finding> = findings
            .into_iter()
            .filter(|f| {
                let (matched, reason) = self.matches_with_tracking(f);
                if !matched {
                    if let Some(r) = reason {
                        match r {
                            FilterReason::Severity(sev) => {
                                stats.by_severity += 1;
                                *severity_counts.entry(sev).or_insert(0) += 1;
                            }
                            FilterReason::RuleNotIncluded(_) => {
                                stats.by_rules_include += 1;
                            }
                            FilterReason::RuleExcluded(rule) => {
                                stats.by_rules_exclude += 1;
                                *excluded_rules.entry(rule).or_insert(0) += 1;
                            }
                            FilterReason::FileNotIncluded(_) => {
                                stats.by_files_include += 1;
                            }
                            FilterReason::FileExcluded(pattern) => {
                                stats.by_files_exclude += 1;
                                *excluded_files.entry(pattern).or_insert(0) += 1;
                            }
                            FilterReason::Category(_) => {
                                stats.by_category += 1;
                            }
                            FilterReason::NotFixable => {
                                stats.by_fixable += 1;
                            }
                            FilterReason::LowConfidence(_) => {
                                stats.by_confidence += 1;
                            }
                            FilterReason::SearchNoMatch => {
                                stats.by_search += 1;
                            }
                        }
                    }
                }
                matched
            })
            .collect();

        stats.total_after = result.len();

        // Build breakdowns
        stats.severity_breakdown = severity_counts.into_iter().collect();
        stats.severity_breakdown.sort_by_key(|(s, _)| *s);

        stats.excluded_rules_breakdown = excluded_rules.into_iter().collect();
        stats.excluded_rules_breakdown.sort_by(|a, b| b.1.cmp(&a.1));

        stats.excluded_files_breakdown = excluded_files.into_iter().collect();
        stats.excluded_files_breakdown.sort_by(|a, b| b.1.cmp(&a.1));

        (result, stats)
    }

    /// Check if any filters are active
    pub fn is_active(&self) -> bool {
        self.min_severity.is_some()
            || !self.rules.is_empty()
            || !self.rules_patterns.is_empty()
            || !self.exclude_rules.is_empty()
            || !self.exclude_rules_patterns.is_empty()
            || !self.file_patterns.is_empty()
            || !self.exclude_patterns.is_empty()
            || self.category.is_some()
            || self.fixable_only
            || self.high_confidence_only
            || self.search_text.is_some()
            || self.search_regex.is_some()
    }

    /// Get a summary of active filters for display
    pub fn summary(&self) -> Vec<(String, String)> {
        let mut items = Vec::new();

        if let Some(sev) = self.min_severity {
            items.push(("Severity".to_string(), format!("{} and above", sev)));
        }

        if !self.rules.is_empty() || !self.rules_patterns.is_empty() {
            let mut all_rules: Vec<_> = self.rules.iter().cloned().collect();
            all_rules.extend(self.rules_patterns.iter().map(|p| p.to_string()));
            items.push(("Rules".to_string(), all_rules.join(", ")));
        }

        if !self.exclude_rules.is_empty() || !self.exclude_rules_patterns.is_empty() {
            let mut all_excluded: Vec<_> = self.exclude_rules.iter().cloned().collect();
            all_excluded.extend(self.exclude_rules_patterns.iter().map(|p| p.to_string()));
            items.push(("Excluded rules".to_string(), all_excluded.join(", ")));
        }

        if !self.file_patterns.is_empty() {
            let patterns: Vec<_> = self.file_patterns.iter().map(|p| p.to_string()).collect();
            items.push(("Files".to_string(), patterns.join(", ")));
        }

        if !self.exclude_patterns.is_empty() {
            let patterns: Vec<_> = self
                .exclude_patterns
                .iter()
                .map(|p| p.to_string())
                .collect();
            items.push(("Excluded files".to_string(), patterns.join(", ")));
        }

        if let Some(cat) = self.category {
            items.push(("Category".to_string(), format!("{}", cat)));
        }

        if self.fixable_only {
            items.push(("Fixable".to_string(), "only".to_string()));
        }

        if self.high_confidence_only {
            items.push(("Confidence".to_string(), "high only".to_string()));
        }

        if let Some(ref regex) = self.search_regex {
            items.push(("Search (regex)".to_string(), regex.to_string()));
        } else if let Some(ref text) = self.search_text {
            items.push(("Search".to_string(), text.clone()));
        }

        items
    }
}

/// Reason why a finding was filtered out
#[derive(Debug, Clone)]
enum FilterReason {
    Severity(Severity),
    #[allow(dead_code)] // Used in matches_with_tracking for explain mode
    RuleNotIncluded(String),
    RuleExcluded(String),
    #[allow(dead_code)] // Used in matches_with_tracking for explain mode
    FileNotIncluded(String),
    FileExcluded(String),
    #[allow(dead_code)] // Used in matches_with_tracking for explain mode
    Category(FindingCategory),
    NotFixable,
    #[allow(dead_code)] // Used in matches_with_tracking for explain mode
    LowConfidence(Confidence),
    SearchNoMatch,
}

/// Load filter profiles from rma.toml
pub fn load_profiles_from_config(
    config_path: &Path,
) -> anyhow::Result<std::collections::HashMap<String, FilterProfile>> {
    let content = std::fs::read_to_string(config_path)?;
    let config: toml::Value = toml::from_str(&content)?;

    let mut profiles = std::collections::HashMap::new();

    if let Some(profiles_table) = config.get("filter_profiles").and_then(|v| v.as_table()) {
        for (name, value) in profiles_table {
            if let Ok(mut profile) = value.clone().try_into::<FilterProfile>() {
                profile.name = name.clone();
                profiles.insert(name.clone(), profile);
            }
        }
    }

    // Also check for legacy [profiles.x] format
    if let Some(profiles_table) = config.get("profiles").and_then(|v| v.as_table()) {
        for (name, value) in profiles_table {
            // Skip the built-in profile names (fast, balanced, strict, default)
            if ["fast", "balanced", "strict", "default"].contains(&name.as_str()) {
                continue;
            }
            if let Ok(mut profile) = value.clone().try_into::<FilterProfile>() {
                profile.name = name.clone();
                profiles.insert(name.clone(), profile);
            }
        }
    }

    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::{Language, SourceLocation};
    use std::path::PathBuf;

    fn make_finding(
        rule_id: &str,
        severity: Severity,
        file: &str,
        category: FindingCategory,
    ) -> Finding {
        Finding {
            id: format!("{}-1", rule_id),
            rule_id: rule_id.to_string(),
            message: format!("Test finding for {}", rule_id),
            severity,
            location: SourceLocation::new(PathBuf::from(file), 1, 1, 1, 10),
            language: Language::Rust,
            snippet: None,
            suggestion: None,
            fix: None,
            confidence: Confidence::High,
            category,
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        }
    }

    #[test]
    fn test_severity_filter() {
        let filter = FindingFilter::new().with_min_severity(Severity::Error);

        let critical = make_finding(
            "test",
            Severity::Critical,
            "test.rs",
            FindingCategory::Security,
        );
        let error = make_finding(
            "test",
            Severity::Error,
            "test.rs",
            FindingCategory::Security,
        );
        let warning = make_finding(
            "test",
            Severity::Warning,
            "test.rs",
            FindingCategory::Security,
        );
        let info = make_finding("test", Severity::Info, "test.rs", FindingCategory::Security);

        assert!(filter.matches(&critical));
        assert!(filter.matches(&error));
        assert!(!filter.matches(&warning));
        assert!(!filter.matches(&info));
    }

    #[test]
    fn test_rule_filter() {
        let filter =
            FindingFilter::new().with_rules(vec!["sql-injection".to_string(), "xss/*".to_string()]);

        let sql = make_finding(
            "sql-injection",
            Severity::Error,
            "test.rs",
            FindingCategory::Security,
        );
        let xss = make_finding(
            "xss/reflected",
            Severity::Error,
            "test.rs",
            FindingCategory::Security,
        );
        let other = make_finding(
            "other-rule",
            Severity::Error,
            "test.rs",
            FindingCategory::Security,
        );

        assert!(filter.matches(&sql));
        assert!(filter.matches(&xss));
        assert!(!filter.matches(&other));
    }

    #[test]
    fn test_exclude_rules() {
        let filter = FindingFilter::new()
            .with_exclude_rules(vec!["style/*".to_string(), "no-console".to_string()]);

        let security = make_finding(
            "sql-injection",
            Severity::Error,
            "test.rs",
            FindingCategory::Security,
        );
        let style = make_finding(
            "style/indent",
            Severity::Warning,
            "test.rs",
            FindingCategory::Style,
        );
        let console = make_finding(
            "no-console",
            Severity::Warning,
            "test.rs",
            FindingCategory::Quality,
        );

        assert!(filter.matches(&security));
        assert!(!filter.matches(&style));
        assert!(!filter.matches(&console));
    }

    #[test]
    fn test_file_filter() {
        let filter = FindingFilter::new()
            .with_files(vec!["src/**/*.rs".to_string()])
            .with_exclude_files(vec!["**/test/**".to_string()]);

        let src = make_finding(
            "test",
            Severity::Error,
            "src/main.rs",
            FindingCategory::Security,
        );
        let test = make_finding(
            "test",
            Severity::Error,
            "src/test/mod.rs",
            FindingCategory::Security,
        );
        let other = make_finding(
            "test",
            Severity::Error,
            "examples/demo.rs",
            FindingCategory::Security,
        );

        assert!(filter.matches(&src));
        assert!(!filter.matches(&test));
        assert!(!filter.matches(&other));
    }

    #[test]
    fn test_category_filter() {
        let filter = FindingFilter::new().with_category(FindingCategory::Security);

        let security = make_finding(
            "test",
            Severity::Error,
            "test.rs",
            FindingCategory::Security,
        );
        let quality = make_finding("test", Severity::Error, "test.rs", FindingCategory::Quality);

        assert!(filter.matches(&security));
        assert!(!filter.matches(&quality));
    }

    #[test]
    fn test_preset_security() {
        let filter = FindingFilter::preset_security();

        assert!(filter.category.is_some());
        assert_eq!(filter.category.unwrap(), FindingCategory::Security);
        assert!(filter.high_confidence_only);
        assert!(filter.min_severity.is_some());
    }

    #[test]
    fn test_search_text() {
        let filter = FindingFilter::new().with_search("injection".to_string());

        let sql = make_finding(
            "sql-injection",
            Severity::Error,
            "test.rs",
            FindingCategory::Security,
        );
        let other = make_finding(
            "other-rule",
            Severity::Error,
            "test.rs",
            FindingCategory::Security,
        );

        assert!(filter.matches(&sql));
        assert!(!filter.matches(&other));
    }

    #[test]
    fn test_combined_filters() {
        let filter = FindingFilter::new()
            .with_min_severity(Severity::Warning)
            .with_category(FindingCategory::Security)
            .with_exclude_files(vec!["**/test/**".to_string()]);

        let matching = make_finding(
            "sql",
            Severity::Error,
            "src/main.rs",
            FindingCategory::Security,
        );
        let low_sev = make_finding(
            "sql",
            Severity::Info,
            "src/main.rs",
            FindingCategory::Security,
        );
        let wrong_cat = make_finding(
            "style",
            Severity::Error,
            "src/main.rs",
            FindingCategory::Style,
        );
        let test_file = make_finding(
            "sql",
            Severity::Error,
            "test/test.rs",
            FindingCategory::Security,
        );

        assert!(filter.matches(&matching));
        assert!(!filter.matches(&low_sev));
        assert!(!filter.matches(&wrong_cat));
        assert!(!filter.matches(&test_file));
    }

    #[test]
    fn test_filter_summary() {
        let filter = FindingFilter::new()
            .with_min_severity(Severity::Error)
            .with_rules(vec!["sql-*".to_string()])
            .with_exclude_files(vec!["**/test/**".to_string()]);

        let summary = filter.summary();
        assert_eq!(summary.len(), 3);
    }
}
