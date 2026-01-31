//! Rule trait and base implementations for security vulnerability DETECTION

use rma_common::{Confidence, Finding, FindingCategory, Language};
use rma_parser::ParsedFile;
use tree_sitter::Node;

/// A security or code quality rule that DETECTS vulnerabilities
pub trait Rule: Send + Sync {
    /// Unique identifier for this rule
    fn id(&self) -> &str;

    /// Human-readable description
    fn description(&self) -> &str;

    /// Languages this rule applies to
    fn applies_to(&self, lang: Language) -> bool;

    /// Check a parsed file and return any findings (detected vulnerabilities)
    fn check(&self, parsed: &ParsedFile) -> Vec<Finding>;
}

/// Helper to create a finding from a line number (for line-based checks)
pub fn create_finding_at_line(
    rule_id: &str,
    path: &std::path::Path,
    line: usize,
    snippet: &str,
    severity: rma_common::Severity,
    message: &str,
    language: Language,
) -> Finding {
    let mut finding = Finding {
        id: format!("{}-{}-1", rule_id, line),
        rule_id: rule_id.to_string(),
        message: message.to_string(),
        severity,
        location: rma_common::SourceLocation::new(path.to_path_buf(), line, 1, line, snippet.len()),
        language,
        snippet: Some(snippet.to_string()),
        suggestion: None,
        confidence: Confidence::Medium,
        category: infer_category(rule_id),
        fingerprint: None,
    };
    finding.compute_fingerprint();
    finding
}

/// Helper to create a finding from a tree-sitter node
pub fn create_finding(
    rule_id: &str,
    node: &Node,
    path: &std::path::Path,
    content: &str,
    severity: rma_common::Severity,
    message: &str,
    language: Language,
) -> Finding {
    let start = node.start_position();
    let end = node.end_position();

    let snippet = node.utf8_text(content.as_bytes()).ok().map(|s: &str| {
        if s.chars().count() > 200 {
            // Safely truncate at char boundary
            let truncated: String = s.chars().take(200).collect();
            format!("{}...", truncated)
        } else {
            s.to_string()
        }
    });

    let mut finding = Finding {
        id: format!("{}-{}-{}", rule_id, start.row, start.column),
        rule_id: rule_id.to_string(),
        message: message.to_string(),
        severity,
        location: rma_common::SourceLocation::new(
            path.to_path_buf(),
            start.row + 1,
            start.column + 1,
            end.row + 1,
            end.column + 1,
        ),
        language,
        snippet,
        suggestion: None,
        confidence: Confidence::Medium,
        category: infer_category(rule_id),
        fingerprint: None,
    };
    finding.compute_fingerprint();
    finding
}

/// Create a finding with explicit confidence level
#[allow(clippy::too_many_arguments)]
pub fn create_finding_with_confidence(
    rule_id: &str,
    node: &Node,
    path: &std::path::Path,
    content: &str,
    severity: rma_common::Severity,
    message: &str,
    language: Language,
    confidence: Confidence,
) -> Finding {
    let mut finding = create_finding(rule_id, node, path, content, severity, message, language);
    finding.confidence = confidence;
    finding
}

/// Infer category from rule ID prefix
fn infer_category(rule_id: &str) -> FindingCategory {
    // Security patterns
    if rule_id.contains("injection")
        || rule_id.contains("xss")
        || rule_id.contains("unsafe")
        || rule_id.contains("secret")
        || rule_id.contains("crypto")
        || rule_id.contains("traversal")
        || rule_id.contains("eval")
        || rule_id.contains("exec")
        || rule_id.contains("transmute")
        || rule_id.contains("deserialization")
    {
        return FindingCategory::Security;
    }

    // Quality patterns
    if rule_id.contains("complexity")
        || rule_id.contains("long-function")
        || rule_id.contains("unwrap")
        || rule_id.contains("expect")
        || rule_id.contains("panic")
    {
        return FindingCategory::Quality;
    }

    // Style patterns
    if rule_id.contains("todo")
        || rule_id.contains("fixme")
        || rule_id.contains("console")
        || rule_id.contains("style")
    {
        return FindingCategory::Style;
    }

    // Default based on path prefix
    if rule_id.starts_with("security/") || rule_id.contains("/sql") || rule_id.contains("/command")
    {
        FindingCategory::Security
    } else if rule_id.starts_with("quality/") || rule_id.contains("/quality") {
        FindingCategory::Quality
    } else if rule_id.starts_with("style/") || rule_id.starts_with("generic/todo") {
        FindingCategory::Style
    } else {
        FindingCategory::Quality // Default to quality
    }
}
