//! Rust-specific security vulnerability DETECTION rules

use crate::rules::{create_finding, Rule};
use rma_common::{Finding, Language, Severity};
use rma_parser::ParsedFile;
use tree_sitter::Node;

/// DETECTS unsafe blocks in Rust code (security audit)
pub struct UnsafeBlockRule;

impl Rule for UnsafeBlockRule {
    fn id(&self) -> &str {
        "rust/unsafe-block"
    }

    fn description(&self) -> &str {
        "Detects unsafe blocks that require manual security review"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();
        find_nodes_by_kind(&mut cursor, "unsafe_block", |node: Node| {
            findings.push(create_finding(
                self.id(),
                &node,
                &parsed.path,
                &parsed.content,
                Severity::Warning,
                "Unsafe block requires manual security review",
                Language::Rust,
            ));
        });
        findings
    }
}

/// DETECTS .unwrap() calls that may panic (reliability issue)
pub struct UnwrapRule;

impl Rule for UnwrapRule {
    fn id(&self) -> &str {
        "rust/unwrap-used"
    }

    fn description(&self) -> &str {
        "Detects .unwrap() calls that may cause panics"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                if text.contains(".unwrap()") || text.contains(".expect(") {
                    findings.push(create_finding(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Info,
                        "Consider using ? operator or proper error handling instead of unwrap/expect",
                        Language::Rust,
                    ));
                }
            }
        });
        findings
    }
}

/// DETECTS panic! macro usage
pub struct PanicRule;

impl Rule for PanicRule {
    fn id(&self) -> &str {
        "rust/panic-used"
    }

    fn description(&self) -> &str {
        "Detects panic! macro calls that may crash the program"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "macro_invocation", |node: Node| {
            if let Some(macro_node) = node.child_by_field_name("macro") {
                if let Ok(text) = macro_node.utf8_text(parsed.content.as_bytes()) {
                    if text == "panic" || text == "todo" || text == "unimplemented" {
                        findings.push(create_finding(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "Panic macro may crash the program unexpectedly",
                            Language::Rust,
                        ));
                    }
                }
            }
        });
        findings
    }
}

/// Helper to find all nodes of a specific kind
fn find_nodes_by_kind<F>(cursor: &mut tree_sitter::TreeCursor, kind: &str, mut callback: F)
where
    F: FnMut(Node),
{
    loop {
        let node = cursor.node();
        if node.kind() == kind {
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

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::RmaConfig;
    use rma_parser::ParserEngine;
    use std::path::Path;

    #[test]
    fn test_unsafe_detection() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
fn main() {
    unsafe {
        let ptr = std::ptr::null::<i32>();
    }
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnsafeBlockRule;
        let findings = rule.check(&parsed);

        assert!(!findings.is_empty());
        assert!(findings[0].rule_id.contains("unsafe"));
    }
}
