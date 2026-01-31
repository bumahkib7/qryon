//! Rust-specific security rules
//!
//! Categorized into:
//! - **Sinks (High Confidence)**: Precise detection of dangerous patterns
//! - **Review Hints (Low Confidence)**: Patterns that need human review

use crate::rules::{create_finding_with_confidence, Rule};
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use tree_sitter::Node;

// =============================================================================
// SECTION A: HIGH-CONFIDENCE SINKS
// These detect actual dangerous patterns with high precision
// =============================================================================

/// Detects `unsafe` blocks - requires security review
/// Confidence: HIGH (AST-based, precise)
pub struct UnsafeBlockRule;

impl Rule for UnsafeBlockRule {
    fn id(&self) -> &str {
        "rust/unsafe-block"
    }

    fn description(&self) -> &str {
        "Detects unsafe blocks that bypass Rust's safety guarantees"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // AST node type "unsafe_block" is precise
        find_nodes_by_kind(&mut cursor, "unsafe_block", |node: Node| {
            findings.push(create_finding_with_confidence(
                self.id(),
                &node,
                &parsed.path,
                &parsed.content,
                Severity::Warning,
                "Unsafe block bypasses Rust's memory safety - requires manual review",
                Language::Rust,
                Confidence::High,
            ));
        });
        findings
    }
}

/// Detects `std::mem::transmute` - type safety bypass
/// Confidence: HIGH (checks actual function call via scoped_identifier)
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
            if let Some(func) = node.child(0) {
                // Must be scoped_identifier (not string literal)
                if func.kind() == "scoped_identifier" || func.kind() == "identifier" {
                    let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                    // Precise match: mem::transmute, std::mem::transmute, transmute_copy
                    if func_text.ends_with("::transmute")
                        || func_text.ends_with("::transmute_copy")
                        || func_text == "transmute"
                        || func_text == "transmute_copy"
                    {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Error,
                            "std::mem::transmute bypasses type safety - ensure this is necessary",
                            Language::Rust,
                            Confidence::High,
                        ));
                    }
                }
            }
        });
        findings
    }
}

/// Detects `Command::new` with shell execution - command injection sink
/// Confidence: HIGH (precise AST pattern)
pub struct CommandInjectionRule;

impl Rule for CommandInjectionRule {
    fn id(&self) -> &str {
        "rust/command-injection"
    }

    fn description(&self) -> &str {
        "Detects shell command execution sinks"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child(0) {
                let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                // HIGH: Command::new with shell
                if func_text.ends_with("Command::new") || func_text == "Command::new" {
                    // Check arguments for shell invocation
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let args_text = args.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                        if args_text.contains("\"sh\"")
                            || args_text.contains("\"bash\"")
                            || args_text.contains("\"/bin/sh\"")
                            || args_text.contains("\"/bin/bash\"")
                            || args_text.contains("\"cmd\"")
                            || args_text.contains("\"powershell\"")
                        {
                            findings.push(create_finding_with_confidence(
                                self.id(),
                                &node,
                                &parsed.path,
                                &parsed.content,
                                Severity::Critical,
                                "Shell command execution - validate all inputs to prevent injection",
                                Language::Rust,
                                Confidence::High,
                            ));
                        }
                    }
                }
            }
        });
        findings
    }
}

/// Detects raw pointer dereferences
/// Confidence: HIGH (AST-based, inside unsafe blocks)
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

        // Look for dereference expressions inside unsafe blocks
        find_nodes_by_kind(&mut cursor, "unsafe_block", |unsafe_node: Node| {
            let mut inner_cursor = unsafe_node.walk();
            find_nodes_in_subtree(&mut inner_cursor, "unary_expression", |node: Node| {
                if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                    // Dereference operator on pointer
                    if text.starts_with('*') {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "Raw pointer dereference - ensure pointer validity",
                            Language::Rust,
                            Confidence::High,
                        ));
                    }
                }
            });
        });
        findings
    }
}

// =============================================================================
// SECTION B: REVIEW HINTS (LOW CONFIDENCE)
// These are heuristics that may need human verification
// =============================================================================

/// Review hint: SQL query building with string interpolation
/// Confidence: LOW-MEDIUM (heuristic, context-dependent)
pub struct SqlInjectionHint;

impl SqlInjectionHint {
    /// Check for database context indicators
    fn has_db_context(path: &std::path::Path, content: &str) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();

        // Path indicators
        let db_path = path_str.contains("/db/")
            || path_str.contains("/database/")
            || path_str.contains("/repository/")
            || path_str.contains("/dao/")
            || path_str.contains("_repo")
            || path_str.ends_with("_db.rs");

        // Import indicators
        let db_imports = ["sqlx", "diesel", "postgres", "rusqlite", "mysql", "sea_orm"]
            .iter()
            .any(|crate_name| content.contains(&format!("use {}::", crate_name)));

        db_path || db_imports
    }

    /// Check for actual database API usage (high signal)
    fn has_db_api_call(text: &str) -> bool {
        text.contains(".query(")
            || text.contains(".execute(")
            || text.contains("query!(")
            || text.contains("query_as!(")
            || text.contains(".prepare(")
    }
}

impl Rule for SqlInjectionHint {
    fn id(&self) -> &str {
        "rust/sql-injection-hint"
    }

    fn description(&self) -> &str {
        "Review hint: potential SQL injection if input is untrusted"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Only check files with DB context
        if !Self::has_db_context(&parsed.path, &parsed.content) {
            return findings;
        }

        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "macro_invocation", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Check for format! with SQL keywords
                if text.starts_with("format!") && Self::has_db_api_call(text) {
                    let lower = text.to_lowercase();
                    let has_sql = lower.contains("select ")
                        || lower.contains("insert ")
                        || lower.contains("update ")
                        || lower.contains("delete ");

                    if has_sql {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "Potential SQL injection if input is untrusted - use parameterized queries",
                            Language::Rust,
                            Confidence::Medium,
                        ));
                    }
                }
            }
        });
        findings
    }
}

/// Review hint: File operations with dynamic paths
/// Confidence: LOW (heuristic - only flags format! in file ops)
pub struct PathTraversalHint;

impl Rule for PathTraversalHint {
    fn id(&self) -> &str {
        "rust/path-traversal-hint"
    }

    fn description(&self) -> &str {
        "Review hint: file path from untrusted input may allow directory traversal"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // File operation sinks
        const FILE_SINKS: &[&str] = &[
            "File::open",
            "File::create",
            "fs::read",
            "fs::read_to_string",
            "fs::write",
            "fs::remove_file",
            "fs::remove_dir_all",
            "std::fs::read",
            "std::fs::write",
        ];

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child(0) {
                let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                // Check if calling a file operation
                let is_file_sink = FILE_SINKS.iter().any(|sink| func_text.ends_with(sink));

                if is_file_sink {
                    // Check for format! macro in arguments
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let args_text = args.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                        if args_text.contains("format!(") {
                            findings.push(create_finding_with_confidence(
                                self.id(),
                                &node,
                                &parsed.path,
                                &parsed.content,
                                Severity::Info,
                                "File path from dynamic input - validate to prevent directory traversal if untrusted",
                                Language::Rust,
                                Confidence::Low,
                            ));
                        }
                    }
                }
            }
        });
        findings
    }
}

/// Review hint: .unwrap() usage
/// Confidence: LOW (code quality, not security)
pub struct UnwrapHint;

impl Rule for UnwrapHint {
    fn id(&self) -> &str {
        "rust/unwrap-hint"
    }

    fn description(&self) -> &str {
        "Review hint: unwrap/expect may panic"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child(0)
                && func.kind() == "field_expression"
            {
                let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                if func_text.ends_with(".unwrap") || func_text.ends_with(".expect") {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Info,
                        "Consider ? operator or proper error handling",
                        Language::Rust,
                        Confidence::Low,
                    ));
                }
            }
        });
        findings
    }
}

/// Review hint: panic! macro usage
/// Confidence: LOW (code quality)
pub struct PanicHint;

impl Rule for PanicHint {
    fn id(&self) -> &str {
        "rust/panic-hint"
    }

    fn description(&self) -> &str {
        "Review hint: panic macros crash the program"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "macro_invocation", |node: Node| {
            if let Some(macro_node) = node.child_by_field_name("macro") {
                let macro_text = macro_node.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                if macro_text == "panic" || macro_text == "todo" || macro_text == "unimplemented" {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Info,
                        "Panic macro will crash - consider Result/Option for recoverable errors",
                        Language::Rust,
                        Confidence::Low,
                    ));
                }
            }
        });
        findings
    }
}

// =============================================================================
// HELPERS
// =============================================================================

/// Find all nodes of a specific kind in tree
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

/// Find nodes of a specific kind within a subtree
fn find_nodes_in_subtree<F>(cursor: &mut tree_sitter::TreeCursor, kind: &str, mut callback: F)
where
    F: FnMut(Node),
{
    let start_depth = cursor.depth();

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
            if !cursor.goto_parent() || cursor.depth() < start_depth {
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
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn test_transmute_detection() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
fn danger() {
    let x: u32 = unsafe { std::mem::transmute(1.0f32) };
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = TransmuteRule;
        let findings = rule.check(&parsed);

        assert!(!findings.is_empty());
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn test_command_shell_detection() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use std::process::Command;

fn run_shell(cmd: &str) {
    Command::new("sh").arg("-c").arg(cmd).output().unwrap();
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = CommandInjectionRule;
        let findings = rule.check(&parsed);

        assert!(!findings.is_empty());
        assert_eq!(findings[0].confidence, Confidence::High);
    }
}
