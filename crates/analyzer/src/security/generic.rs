//! Generic security and code quality DETECTION rules
//!
//! These rules apply across multiple languages for static analysis.

use crate::rules::{create_finding, Rule};
use rma_common::{Finding, Language, Severity};
use rma_parser::ParsedFile;
use tree_sitter::Node;

/// DETECTS TODO/FIXME comments that may indicate incomplete code
pub struct TodoFixmeRule;

impl Rule for TodoFixmeRule {
    fn id(&self) -> &str {
        "generic/todo-fixme"
    }

    fn description(&self) -> &str {
        "Detects TODO and FIXME comments that may indicate incomplete functionality"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in parsed.content.lines().enumerate() {
            let upper = line.to_uppercase();
            if upper.contains("TODO") || upper.contains("FIXME") || upper.contains("HACK") || upper.contains("XXX") {
                findings.push(Finding {
                    id: format!("{}-{}", self.id(), line_num),
                    rule_id: self.id().to_string(),
                    message: "TODO/FIXME comment indicates potentially incomplete code".to_string(),
                    severity: Severity::Info,
                    location: rma_common::SourceLocation::new(
                        parsed.path.clone(),
                        line_num + 1,
                        1,
                        line_num + 1,
                        line.len(),
                    ),
                    language: parsed.language,
                    snippet: Some(line.trim().to_string()),
                    suggestion: None,
                });
            }
        }
        findings
    }
}

/// DETECTS functions that exceed a line count threshold
pub struct LongFunctionRule {
    max_lines: usize,
}

impl LongFunctionRule {
    pub fn new(max_lines: usize) -> Self {
        Self { max_lines }
    }
}

impl Rule for LongFunctionRule {
    fn id(&self) -> &str {
        "generic/long-function"
    }

    fn description(&self) -> &str {
        "Detects functions that exceed the recommended line count"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        let function_kinds = [
            "function_item",
            "function_declaration",
            "function_definition",
            "method_declaration",
            "arrow_function",
        ];

        find_nodes_by_kinds(&mut cursor, &function_kinds, |node: Node| {
            let start = node.start_position().row;
            let end = node.end_position().row;
            let lines = end - start + 1;

            if lines > self.max_lines {
                findings.push(create_finding(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    &format!("Function has {} lines (max: {}) - consider refactoring", lines, self.max_lines),
                    parsed.language,
                ));
            }
        });
        findings
    }
}

/// DETECTS high cyclomatic complexity
pub struct HighComplexityRule {
    max_complexity: usize,
}

impl HighComplexityRule {
    pub fn new(max_complexity: usize) -> Self {
        Self { max_complexity }
    }
}

impl Rule for HighComplexityRule {
    fn id(&self) -> &str {
        "generic/high-complexity"
    }

    fn description(&self) -> &str {
        "Detects functions with high cyclomatic complexity"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        let function_kinds = [
            "function_item",
            "function_declaration",
            "function_definition",
            "method_declaration",
        ];

        find_nodes_by_kinds(&mut cursor, &function_kinds, |node: Node| {
            let complexity = count_branches(&node, parsed.language);

            if complexity > self.max_complexity {
                findings.push(create_finding(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    &format!(
                        "Function has complexity {} (max: {}) - consider simplifying",
                        complexity, self.max_complexity
                    ),
                    parsed.language,
                ));
            }
        });
        findings
    }
}

fn find_nodes_by_kinds<F>(cursor: &mut tree_sitter::TreeCursor, kinds: &[&str], mut callback: F)
where
    F: FnMut(Node),
{
    loop {
        let node = cursor.node();
        if kinds.contains(&node.kind()) {
            callback(node);
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

fn count_branches(node: &Node, lang: Language) -> usize {
    let branch_kinds: &[&str] = match lang {
        Language::Rust => &["if_expression", "match_expression", "while_expression", "for_expression"],
        Language::JavaScript | Language::TypeScript => &["if_statement", "switch_statement", "for_statement", "while_statement"],
        Language::Python => &["if_statement", "for_statement", "while_statement", "try_statement"],
        Language::Go => &["if_statement", "for_statement", "switch_statement"],
        Language::Java => &["if_statement", "for_statement", "while_statement", "switch_expression"],
        Language::Unknown => &[],
    };

    let mut count = 1;
    let mut cursor = node.walk();

    loop {
        let current = cursor.node();
        if branch_kinds.contains(&current.kind()) {
            count += 1;
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return count;
            }
        }
    }
}
