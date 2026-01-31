//! Rust-specific security vulnerability DETECTION rules

use crate::rules::{Rule, create_finding};
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
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
                && (text.contains(".unwrap()") || text.contains(".expect("))
            {
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
            if let Some(macro_node) = node.child_by_field_name("macro")
                && let Ok(text) = macro_node.utf8_text(parsed.content.as_bytes())
                && (text == "panic" || text == "todo" || text == "unimplemented")
            {
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
        });
        findings
    }
}

/// DETECTS std::mem::transmute usage (type safety bypass)
pub struct TransmuteRule;

impl Rule for TransmuteRule {
    fn id(&self) -> &str {
        "rust/transmute-used"
    }

    fn description(&self) -> &str {
        "Detects std::mem::transmute which bypasses type safety"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Skip detection code patterns
                if text.contains(".contains(") {
                    return;
                }
                if text.contains("transmute") || text.contains("transmute_copy") {
                    findings.push(create_finding(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Error,
                        "std::mem::transmute bypasses type safety - ensure this is absolutely necessary",
                        Language::Rust,
                    ));
                }
            }
        });
        findings
    }
}

/// DETECTS raw pointer dereferences in unsafe blocks
pub struct RawPointerDerefRule;

impl Rule for RawPointerDerefRule {
    fn id(&self) -> &str {
        "rust/raw-pointer-deref"
    }

    fn description(&self) -> &str {
        "Detects raw pointer dereferences which may cause undefined behavior"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Look for dereference of raw pointers
        find_nodes_by_kind(&mut cursor, "unary_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Check for *ptr patterns with raw pointer types
                if text.starts_with('*')
                    && (text.contains("*const") || text.contains("*mut") || text.contains("as *"))
                {
                    findings.push(create_finding(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "Raw pointer dereference may cause undefined behavior",
                        Language::Rust,
                    ));
                }
            }
        });
        findings
    }
}

/// DETECTS potential command injection via std::process::Command
pub struct CommandInjectionRule;

impl Rule for CommandInjectionRule {
    fn id(&self) -> &str {
        "rust/command-injection"
    }

    fn description(&self) -> &str {
        "Detects potential command injection vulnerabilities"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Skip detection code patterns
                if text.contains(".contains(") {
                    return;
                }
                // Detect Command::new with shell or sh
                if (text.contains("Command::new") || text.contains("process::Command"))
                    && (text.contains("\"sh\"")
                        || text.contains("\"bash\"")
                        || text.contains("\"/bin/sh\"")
                        || text.contains("shell"))
                {
                    findings.push(create_finding(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Critical,
                        "Shell command execution detected - ensure input is properly sanitized",
                        Language::Rust,
                    ));
                }
                // Detect .arg() with format! or variable interpolation
                if text.contains(".arg(") && (text.contains("format!") || text.contains("&format"))
                {
                    findings.push(create_finding(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "Command argument uses string interpolation - verify input is sanitized",
                        Language::Rust,
                    ));
                }
            }
        });
        findings
    }
}

/// DETECTS SQL query construction with string formatting (SQL injection risk)
pub struct SqlInjectionRule;

impl Rule for SqlInjectionRule {
    fn id(&self) -> &str {
        "rust/sql-injection"
    }

    fn description(&self) -> &str {
        "Detects potential SQL injection from string concatenation in queries"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "macro_invocation", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Check for format! with SQL keywords
                if text.contains("format!") {
                    let lower = text.to_lowercase();
                    if lower.contains("select")
                        || lower.contains("insert")
                        || lower.contains("update")
                        || lower.contains("delete")
                        || lower.contains("drop")
                        || lower.contains("exec")
                    {
                        findings.push(create_finding(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Critical,
                            "SQL query built with format! - use parameterized queries instead",
                            Language::Rust,
                        ));
                    }
                }
            }
        });

        // Also check for raw string SQL with concatenation
        let mut cursor2 = parsed.tree.walk();
        find_nodes_by_kind(&mut cursor2, "binary_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                let lower = text.to_lowercase();
                if (lower.contains("select ")
                    || lower.contains("insert ")
                    || lower.contains("update "))
                    && text.contains('+')
                {
                    findings.push(create_finding(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Critical,
                        "SQL query uses string concatenation - use parameterized queries",
                        Language::Rust,
                    ));
                }
            }
        });

        findings
    }
}

/// DETECTS unchecked array/slice indexing
pub struct UncheckedIndexRule;

impl Rule for UncheckedIndexRule {
    fn id(&self) -> &str {
        "rust/unchecked-index"
    }

    fn description(&self) -> &str {
        "Detects direct array indexing that may panic on out-of-bounds"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "index_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Skip .get() calls which are safe
                if text.contains(".get(") || text.contains(".get_mut(") {
                    return;
                }
                // Check for variable index (not constant)
                if text.contains('[') && !text.contains("[0]") && !text.contains("[1]") {
                    // Likely a variable index - could panic
                    findings.push(create_finding(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Info,
                        "Consider using .get() for bounds-checked indexing",
                        Language::Rust,
                    ));
                }
            }
        });
        findings
    }
}

/// DETECTS path traversal vulnerabilities
pub struct PathTraversalRule;

impl Rule for PathTraversalRule {
    fn id(&self) -> &str {
        "rust/path-traversal"
    }

    fn description(&self) -> &str {
        "Detects potential path traversal vulnerabilities"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Check for File::open, fs::read, etc. with format! or user input
                if (text.contains("File::open")
                    || text.contains("fs::read")
                    || text.contains("fs::write")
                    || text.contains("Path::new"))
                    && (text.contains("format!") || text.contains("&format"))
                {
                    findings.push(create_finding(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "File path uses string interpolation - validate path to prevent directory traversal",
                        Language::Rust,
                    ));
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
