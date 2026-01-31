//! Rule trait and base implementations for security vulnerability DETECTION

use rma_common::{Finding, Language};
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
    Finding {
        id: format!("{}-{}-1", rule_id, line),
        rule_id: rule_id.to_string(),
        message: message.to_string(),
        severity,
        location: rma_common::SourceLocation::new(
            path.to_path_buf(),
            line,
            1,
            line,
            snippet.len(),
        ),
        language,
        snippet: Some(snippet.to_string()),
        suggestion: None,
    }
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

    Finding {
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
    }
}
