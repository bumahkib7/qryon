//! JavaScript-specific security vulnerability DETECTION rules
//!
//! These rules DETECT dangerous patterns in JavaScript code for security auditing.

use crate::rules::{create_finding, Rule};
use rma_common::{Finding, Language, Severity};
use rma_parser::ParsedFile;
use tree_sitter::Node;

/// DETECTS dangerous dynamic code execution patterns (security vulnerability detection)
pub struct DynamicCodeExecutionRule;

impl Rule for DynamicCodeExecutionRule {
    fn id(&self) -> &str {
        "js/dynamic-code-execution"
    }

    fn description(&self) -> &str {
        "Detects dangerous dynamic code execution patterns that may lead to code injection"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Dangerous function names to detect (not execute!)
        let dangerous_functions = ["eval", "Function", "setTimeout", "setInterval"];

        find_call_expressions(&mut cursor, |node: Node| {
            if let Some(func) = node.child_by_field_name("function") {
                if let Ok(text) = func.utf8_text(parsed.content.as_bytes()) {
                    if dangerous_functions.contains(&text) {
                        findings.push(create_finding(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Critical,
                            &format!("Detected dangerous {} call - potential code injection vulnerability", text),
                            Language::JavaScript,
                        ));
                    }
                }
            }
        });
        findings
    }
}

/// DETECTS innerHTML usage (XSS vulnerability detection)
pub struct InnerHtmlRule;

impl Rule for InnerHtmlRule {
    fn id(&self) -> &str {
        "js/innerhtml-xss"
    }

    fn description(&self) -> &str {
        "Detects innerHTML assignments that may lead to XSS vulnerabilities"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_member_expressions(&mut cursor, |node: Node| {
            if let Some(prop) = node.child_by_field_name("property") {
                if let Ok(text) = prop.utf8_text(parsed.content.as_bytes()) {
                    if text == "innerHTML" || text == "outerHTML" {
                        findings.push(create_finding(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Error,
                            "innerHTML/outerHTML usage detected - potential XSS vulnerability. Use textContent or sanitize input.",
                            Language::JavaScript,
                        ));
                    }
                }
            }
        });
        findings
    }
}

/// DETECTS console.log statements (code quality issue detection)
pub struct ConsoleLogRule;

impl Rule for ConsoleLogRule {
    fn id(&self) -> &str {
        "js/console-log"
    }

    fn description(&self) -> &str {
        "Detects console.log statements that should be removed in production"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_call_expressions(&mut cursor, |node: Node| {
            if let Some(func) = node.child_by_field_name("function") {
                if let Ok(text) = func.utf8_text(parsed.content.as_bytes()) {
                    if text.starts_with("console.") {
                        findings.push(create_finding(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Info,
                            "console statement detected - consider removing for production",
                            Language::JavaScript,
                        ));
                    }
                }
            }
        });
        findings
    }
}

fn find_call_expressions<F>(cursor: &mut tree_sitter::TreeCursor, mut callback: F)
where
    F: FnMut(Node),
{
    loop {
        let node = cursor.node();
        if node.kind() == "call_expression" {
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

fn find_member_expressions<F>(cursor: &mut tree_sitter::TreeCursor, mut callback: F)
where
    F: FnMut(Node),
{
    loop {
        let node = cursor.node();
        if node.kind() == "member_expression" {
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
