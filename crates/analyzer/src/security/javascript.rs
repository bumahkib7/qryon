//! JavaScript-specific security vulnerability DETECTION rules
//!
//! These rules DETECT dangerous patterns in JavaScript code for security auditing.
//! This is a security analysis tool - it detects but does not execute dangerous code.

use crate::rules::{Rule, create_finding};
use rma_common::{Finding, Language, Severity};
use rma_parser::ParsedFile;
use tree_sitter::Node;

/// DETECTS dangerous dynamic code execution patterns (security vulnerability detection)
/// This rule detects uses of dangerous APIs like the eval function and Function constructor
pub struct DynamicCodeExecutionRule;

impl Rule for DynamicCodeExecutionRule {
    fn id(&self) -> &str {
        "js/dynamic-code-execution"
    }

    fn description(&self) -> &str {
        "Detects dangerous code execution APIs that may lead to code injection"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Only truly dangerous functions - NOT setTimeout/setInterval (handled by TimerStringRule)
        // NOTE: This is a DETECTION rule - we identify dangerous patterns, we don't execute them
        let dangerous_api_names = ["eval", "Function"];

        find_call_expressions(&mut cursor, |node: Node| {
            if let Some(func) = node.child_by_field_name("function")
                && let Ok(text) = func.utf8_text(parsed.content.as_bytes())
                && dangerous_api_names.contains(&text)
            {
                findings.push(create_finding(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Critical,
                    &format!(
                        "Detected dangerous {} call - potential code injection vulnerability",
                        text
                    ),
                    Language::JavaScript,
                ));
            }
        });
        findings
    }
}

/// DETECTS setTimeout/setInterval with string argument (behaves like code execution)
///
/// Only flags when the first argument is:
/// - A string literal ("code")
/// - A template literal (`code`)
/// - String concatenation ("code" + variable)
///
/// Does NOT flag when the first argument is:
/// - A function reference (foo)
/// - An arrow function (() => {})
/// - A function expression (function() {})
pub struct TimerStringRule;

impl Rule for TimerStringRule {
    fn id(&self) -> &str {
        "js/timer-string-eval"
    }

    fn description(&self) -> &str {
        "Detects setTimeout/setInterval with string argument which executes code dynamically"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_call_expressions(&mut cursor, |node: Node| {
            if let Some(func) = node.child_by_field_name("function")
                && let Ok(text) = func.utf8_text(parsed.content.as_bytes())
                && (text == "setTimeout" || text == "setInterval")
                && let Some(args) = node.child_by_field_name("arguments")
                && let Some(first_arg) = args.named_child(0)
                && is_string_like_argument(&first_arg)
            {
                findings.push(create_finding(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    &format!(
                        "String passed to {} behaves like dynamic code execution; use a function instead.",
                        text
                    ),
                    Language::JavaScript,
                ));
            }
        });
        findings
    }
}

/// Check if a node is a string-like argument (string literal, template literal, or concatenation)
fn is_string_like_argument(node: &Node) -> bool {
    match node.kind() {
        // Direct string literal: "code"
        "string" | "string_fragment" => true,
        // Template literal: `code`
        "template_string" => true,
        // String concatenation: "code" + x
        "binary_expression" => {
            // Check if it's string concatenation (at least one operand is a string)
            if let Some(left) = node.child_by_field_name("left")
                && is_string_like_argument(&left)
            {
                return true;
            }
            if let Some(right) = node.child_by_field_name("right")
                && is_string_like_argument(&right)
            {
                return true;
            }
            false
        }
        _ => false,
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
            if let Some(prop) = node.child_by_field_name("property")
                && let Ok(text) = prop.utf8_text(parsed.content.as_bytes())
                && (text == "innerHTML" || text == "outerHTML")
            {
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
            if let Some(func) = node.child_by_field_name("function")
                && let Ok(text) = func.utf8_text(parsed.content.as_bytes())
                && text.starts_with("console.")
            {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;
    use rma_common::RmaConfig;
    use rma_parser::ParserEngine;
    use std::path::Path;

    fn parse_js(content: &str) -> ParsedFile {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);
        parser.parse_file(Path::new("test.js"), content).unwrap()
    }

    #[test]
    fn test_timer_arrow_function_not_flagged() {
        // setTimeout(() => foo(), 100) should NOT be flagged
        let content = r#"setTimeout(() => foo(), 100);"#;
        let parsed = parse_js(content);
        let rule = TimerStringRule;
        let findings = rule.check(&parsed);
        assert!(findings.is_empty(), "Arrow function should not be flagged");
    }

    #[test]
    fn test_timer_function_reference_not_flagged() {
        // setTimeout(foo, 100) should NOT be flagged
        let content = r#"setTimeout(foo, 100);"#;
        let parsed = parse_js(content);
        let rule = TimerStringRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Function reference should not be flagged"
        );
    }

    #[test]
    fn test_timer_string_literal_flagged() {
        // setTimeout("foo()", 100) SHOULD be flagged
        let content = r#"setTimeout("foo()", 100);"#;
        let parsed = parse_js(content);
        let rule = TimerStringRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "String literal should be flagged");
        assert!(findings[0].message.contains("String passed to setTimeout"));
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_setinterval_string_flagged() {
        // setInterval("alert(1)", 100) SHOULD be flagged
        let content = r#"setInterval("alert(1)", 100);"#;
        let parsed = parse_js(content);
        let rule = TimerStringRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "setInterval with string should be flagged"
        );
        assert!(findings[0].message.contains("String passed to setInterval"));
    }

    #[test]
    fn test_timer_template_literal_flagged() {
        // setTimeout(`foo()`, 100) SHOULD be flagged
        let content = "setTimeout(`foo()`, 100);";
        let parsed = parse_js(content);
        let rule = TimerStringRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "Template literal should be flagged");
    }

    #[test]
    fn test_timer_function_expression_not_flagged() {
        // setTimeout(function() { foo(); }, 100) should NOT be flagged
        let content = r#"setTimeout(function() { foo(); }, 100);"#;
        let parsed = parse_js(content);
        let rule = TimerStringRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Function expression should not be flagged"
        );
    }
}
