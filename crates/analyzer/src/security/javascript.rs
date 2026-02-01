//! JavaScript-specific security vulnerability DETECTION rules
//!
//! These rules DETECT dangerous patterns in JavaScript code for security auditing.
//! This is a security analysis tool - it detects but does not execute dangerous code.

use crate::rules::{Rule, create_finding, create_finding_with_confidence};
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use std::collections::HashSet;
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

/// DETECTS dangerous HTML property WRITE patterns (XSS sink vulnerability detection)
///
/// Only flags WRITE/assignment patterns like:
/// - `el.innerHTML = userInput`
/// - `el.outerHTML = userInput`
///
/// READ patterns (e.g., `const x = el.innerHTML`) are handled by InnerHtmlReadRule
/// with lower severity since they don't directly cause XSS.
pub struct InnerHtmlRule;

impl InnerHtmlRule {
    /// Properties that can cause XSS when written to
    const DANGEROUS_PROPS: &'static [&'static str] = &["innerHTML", "outerHTML"];

    /// Check if a member_expression node is on the LEFT side of an assignment
    fn is_assignment_target(node: &Node) -> bool {
        if let Some(parent) = node.parent() {
            // Check if parent is an assignment_expression
            if parent.kind() == "assignment_expression" {
                // Check if this node is the left side
                if let Some(left) = parent.child_by_field_name("left") {
                    return left.id() == node.id();
                }
            }
            // Also check augmented assignment: el.innerHTML += x
            if parent.kind() == "augmented_assignment_expression"
                && let Some(left) = parent.child_by_field_name("left")
            {
                return left.id() == node.id();
            }
        }
        false
    }
}

impl Rule for InnerHtmlRule {
    fn id(&self) -> &str {
        "js/innerhtml-xss"
    }

    fn description(&self) -> &str {
        "Detects dangerous HTML property assignments (XSS sinks)"
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
                && Self::DANGEROUS_PROPS.contains(&text)
                && Self::is_assignment_target(&node)
            {
                findings.push(create_finding_with_confidence(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Error,
                    &format!(
                        "{} assignment detected - XSS sink. Sanitize input or use textContent.",
                        text
                    ),
                    Language::JavaScript,
                    Confidence::High,
                ));
            }
        });
        findings
    }
}

/// DETECTS dangerous HTML property READ patterns (informational)
///
/// READ patterns like `const x = el.innerHTML` are flagged at INFO level
/// since reading doesn't directly cause XSS but may indicate patterns
/// worth reviewing (e.g., storing and later writing unsanitized content).
pub struct InnerHtmlReadRule;

impl Rule for InnerHtmlReadRule {
    fn id(&self) -> &str {
        "js/innerhtml-read"
    }

    fn description(&self) -> &str {
        "Detects dangerous HTML property read access (informational)"
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
                && InnerHtmlRule::DANGEROUS_PROPS.contains(&text)
                && !InnerHtmlRule::is_assignment_target(&node)
            {
                findings.push(create_finding_with_confidence(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Info,
                    &format!(
                        "{} read detected - review if content is later written unsanitized",
                        text
                    ),
                    Language::JavaScript,
                    Confidence::Low,
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

// =============================================================================
// PRIORITY 1: Additional Security Sinks
// =============================================================================

/// DETECTS javascript: URLs in JSX/HTML attributes (XSS vulnerability)
pub struct JsxScriptUrlRule;

impl Rule for JsxScriptUrlRule {
    fn id(&self) -> &str {
        "js/jsx-no-script-url"
    }

    fn description(&self) -> &str {
        "Detects javascript: URLs which can execute arbitrary code"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "string", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Use case-insensitive search without allocation
                if contains_ignore_case(text, "javascript:") {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Critical,
                        "javascript: URL detected - XSS vulnerability. Use onClick handler instead.",
                        Language::JavaScript,
                        Confidence::High,
                    ));
                }
            }
        });
        findings
    }
}

/// Case-insensitive substring search without allocation
#[inline]
fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// DETECTS React's dangerous HTML escape hatch
pub struct DangerousHtmlRule;

impl Rule for DangerousHtmlRule {
    fn id(&self) -> &str {
        "js/dangerous-html"
    }

    fn description(&self) -> &str {
        "Detects React props that bypass XSS protection"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen_lines: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut cursor = parsed.tree.walk();

        // The prop name we're looking for (React's raw HTML prop)
        const DANGEROUS_PROP: &str = "dangerouslySetInnerHTML";

        find_nodes_by_kind(&mut cursor, "property_identifier", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
                && text == DANGEROUS_PROP
            {
                let line = node.start_position().row + 1;
                seen_lines.insert(line);
                findings.push(create_finding_with_confidence(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "Raw HTML prop bypasses XSS protection - ensure content is sanitized",
                    Language::JavaScript,
                    Confidence::High,
                ));
            }
        });

        cursor = parsed.tree.walk();
        find_nodes_by_kind(&mut cursor, "jsx_attribute", |node: Node| {
            let line = node.start_position().row + 1;
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
                && text.contains(DANGEROUS_PROP)
                && !seen_lines.contains(&line)
            // O(1) lookup instead of O(n)
            {
                seen_lines.insert(line);
                findings.push(create_finding_with_confidence(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "Raw HTML prop bypasses XSS protection - ensure content is sanitized",
                    Language::JavaScript,
                    Confidence::High,
                ));
            }
        });
        findings
    }
}

/// DETECTS debugger statements
pub struct DebuggerStatementRule;

impl Rule for DebuggerStatementRule {
    fn id(&self) -> &str {
        "js/no-debugger"
    }

    fn description(&self) -> &str {
        "Detects debugger statements that should not be in production code"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "debugger_statement", |node: Node| {
            findings.push(create_finding(
                self.id(),
                &node,
                &parsed.path,
                &parsed.content,
                Severity::Warning,
                "debugger statement detected - remove before production",
                Language::JavaScript,
            ));
        });
        findings
    }
}

/// DETECTS alert/confirm/prompt
pub struct NoAlertRule;

impl Rule for NoAlertRule {
    fn id(&self) -> &str {
        "js/no-alert"
    }

    fn description(&self) -> &str {
        "Detects alert/confirm/prompt which should not be used in production"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        let dialog_functions = ["alert", "confirm", "prompt"];

        find_call_expressions(&mut cursor, |node: Node| {
            if let Some(func) = node.child_by_field_name("function")
                && let Ok(text) = func.utf8_text(parsed.content.as_bytes())
                && dialog_functions.contains(&text)
            {
                findings.push(create_finding(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    &format!("{}() detected - use a proper UI component instead", text),
                    Language::JavaScript,
                ));
            }
        });
        findings
    }
}

// =============================================================================
// PRIORITY 2: Correctness Rules
// =============================================================================

/// DETECTS == and != instead of === and !==
pub struct StrictEqualityRule;

impl Rule for StrictEqualityRule {
    fn id(&self) -> &str {
        "js/eqeqeq"
    }

    fn description(&self) -> &str {
        "Detects == and != which can cause type coercion bugs"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "binary_expression", |node: Node| {
            if let Some(op) = node.child_by_field_name("operator")
                && let Ok(op_text) = op.utf8_text(parsed.content.as_bytes())
            {
                let (is_loose, suggestion) = match op_text {
                    "==" => (true, "==="),
                    "!=" => (true, "!=="),
                    _ => (false, ""),
                };

                if is_loose {
                    // Skip null checks: x == null is a common pattern
                    if let Some(right) = node.child_by_field_name("right")
                        && let Ok(right_text) = right.utf8_text(parsed.content.as_bytes())
                        && (right_text == "null" || right_text == "undefined")
                    {
                        return;
                    }
                    if let Some(left) = node.child_by_field_name("left")
                        && let Ok(left_text) = left.utf8_text(parsed.content.as_bytes())
                        && (left_text == "null" || left_text == "undefined")
                    {
                        return;
                    }

                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        &format!(
                            "Use {} instead of {} to avoid type coercion",
                            suggestion, op_text
                        ),
                        Language::JavaScript,
                        Confidence::High,
                    ));
                }
            }
        });
        findings
    }
}

/// DETECTS assignment in conditions (if/while/for/do-while)
///
/// Only flags assignments inside actual control flow conditions, NOT:
/// - Ternary expressions in JSX/template literals (these are intentional)
/// - Assignments wrapped in parentheses and compared (intentional pattern)
pub struct NoConditionAssignRule;

impl Rule for NoConditionAssignRule {
    fn id(&self) -> &str {
        "js/no-cond-assign"
    }

    fn description(&self) -> &str {
        "Detects assignments in conditions which are usually bugs"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Only check actual control flow statements, NOT ternary expressions
        // Ternaries in JSX/template literals are intentional and not bugs
        find_nodes_by_kinds(
            &mut cursor,
            &[
                "if_statement",
                "while_statement",
                "do_statement",
                "for_statement",
            ],
            |node: Node| {
                if let Some(condition) = node.child_by_field_name("condition") {
                    check_assignment_in_condition(&condition, parsed, self.id(), &mut findings);
                }
            },
        );

        findings
    }
}

/// Check for assignment expressions in a condition
/// Skips intentional patterns like: if ((match = regex.exec(str)) !== null)
fn check_assignment_in_condition(
    node: &Node,
    parsed: &ParsedFile,
    rule_id: &str,
    findings: &mut Vec<Finding>,
) {
    let mut cursor = node.walk();
    loop {
        let current = cursor.node();
        if current.kind() == "assignment_expression" {
            // Skip if the assignment is part of a comparison (intentional pattern)
            // e.g., if ((x = getValue()) !== null)
            let is_intentional = is_intentional_assignment(&current, parsed);

            if !is_intentional {
                findings.push(create_finding_with_confidence(
                    rule_id,
                    &current,
                    &parsed.path,
                    &parsed.content,
                    Severity::Error,
                    "Assignment in condition - did you mean === ?",
                    Language::JavaScript,
                    Confidence::High,
                ));
            }
        }

        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() || cursor.node().id() == node.id() {
                return;
            }
        }
    }
}

/// Check if an assignment is intentional (wrapped in parens and compared)
fn is_intentional_assignment(node: &Node, parsed: &ParsedFile) -> bool {
    // Pattern: ((x = getValue()) !== null)
    // Check if parent is parenthesized_expression and grandparent is binary_expression with comparison
    if let Some(parent) = node.parent()
        && parent.kind() == "parenthesized_expression"
        && let Some(grandparent) = parent.parent()
        && grandparent.kind() == "binary_expression"
        && let Ok(text) = grandparent.utf8_text(parsed.content.as_bytes())
    {
        return text.contains("===")
            || text.contains("!==")
            || text.contains("== ")
            || text.contains("!= ");
    }
    false
}

/// DETECTS constant conditions
pub struct NoConstantConditionRule;

impl Rule for NoConstantConditionRule {
    fn id(&self) -> &str {
        "js/no-constant-condition"
    }

    fn description(&self) -> &str {
        "Detects constant conditions which indicate dead code or infinite loops"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "if_statement", |node: Node| {
            if let Some(condition) = node.child_by_field_name("condition")
                && is_constant_cond(&condition)
            {
                findings.push(create_finding_with_confidence(
                    self.id(),
                    &condition,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "Constant condition - code path always/never taken",
                    Language::JavaScript,
                    Confidence::High,
                ));
            }
        });

        findings
    }
}

fn is_constant_cond(node: &Node) -> bool {
    match node.kind() {
        "true" | "false" | "number" | "null" => true,
        "parenthesized_expression" => node
            .named_child(0)
            .map(|n| is_constant_cond(&n))
            .unwrap_or(false),
        _ => false,
    }
}

/// DETECTS invalid typeof comparisons
pub struct ValidTypeofRule;

impl Rule for ValidTypeofRule {
    fn id(&self) -> &str {
        "js/valid-typeof"
    }

    fn description(&self) -> &str {
        "Detects invalid typeof comparison strings"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        let valid_types = [
            "undefined",
            "object",
            "boolean",
            "number",
            "string",
            "function",
            "symbol",
            "bigint",
        ];

        find_nodes_by_kind(&mut cursor, "binary_expression", |node: Node| {
            // Get left and right operands
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");

            // Check if this is actually a typeof comparison:
            // typeof x === "string" or "string" === typeof x
            let (typeof_side, string_side) = match (&left, &right) {
                (Some(l), Some(r)) if is_typeof_expression(l) => (Some(l), Some(r)),
                (Some(l), Some(r)) if is_typeof_expression(r) => (Some(r), Some(l)),
                _ => (None, None),
            };

            // Only proceed if we have a typeof expression on one side
            if typeof_side.is_none() {
                return;
            }

            // Check if the other side is a string literal
            if let Some(str_node) = string_side
                && str_node.kind() == "string"
                && let Ok(str_text) = str_node.utf8_text(parsed.content.as_bytes())
            {
                let inner = str_text.trim_matches(|c| c == '"' || c == '\'' || c == '`');
                if !valid_types.contains(&inner) {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        str_node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Error,
                        &format!("Invalid typeof comparison: '{}' is not a valid type", inner),
                        Language::JavaScript,
                        Confidence::High,
                    ));
                }
            }
        });
        findings
    }
}

/// Check if a node is a typeof unary expression
fn is_typeof_expression(node: &Node) -> bool {
    // typeof produces a "unary_expression" in tree-sitter-javascript
    // with the operator as "typeof"
    if node.kind() == "unary_expression" {
        // Check if first child is "typeof" operator
        if let Some(first_child) = node.child(0) {
            return first_child.kind() == "typeof";
        }
    }
    false
}

/// DETECTS with statements
pub struct NoWithRule;

impl Rule for NoWithRule {
    fn id(&self) -> &str {
        "js/no-with"
    }

    fn description(&self) -> &str {
        "Detects with statements which are deprecated"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "with_statement", |node: Node| {
            findings.push(create_finding_with_confidence(
                self.id(),
                &node,
                &parsed.path,
                &parsed.content,
                Severity::Error,
                "with statement is deprecated and forbidden in strict mode",
                Language::JavaScript,
                Confidence::High,
            ));
        });
        findings
    }
}

/// DETECTS document.write
pub struct NoDocumentWriteRule;

impl Rule for NoDocumentWriteRule {
    fn id(&self) -> &str {
        "js/no-document-write"
    }

    fn description(&self) -> &str {
        "Detects document.write which can cause security and performance issues"
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
                && (text == "document.write" || text == "document.writeln")
            {
                findings.push(create_finding_with_confidence(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "document.write blocks rendering - use DOM manipulation instead",
                    Language::JavaScript,
                    Confidence::High,
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

/// Find nodes matching any of the given kinds in a single tree traversal
fn find_nodes_by_kinds<F>(cursor: &mut tree_sitter::TreeCursor, kinds: &[&str], mut callback: F)
where
    F: FnMut(Node),
{
    // Use HashSet for O(1) lookups
    let kinds_set: HashSet<&str> = kinds.iter().copied().collect();

    loop {
        let node = cursor.node();
        if kinds_set.contains(node.kind()) {
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

    // =========================================================================
    // innerHTML WRITE vs READ tests
    // =========================================================================

    #[test]
    fn test_innerhtml_write_flagged_as_xss() {
        // el.innerHTML = x SHOULD be flagged as XSS sink (Error severity)
        let content = r#"document.getElementById("foo").innerHTML = userInput;"#;
        let parsed = parse_js(content);
        let rule = InnerHtmlRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "innerHTML assignment should be flagged");
        assert_eq!(findings[0].rule_id, "js/innerhtml-xss");
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("assignment"));
    }

    #[test]
    fn test_innerhtml_augmented_assignment_flagged() {
        // el.innerHTML += x SHOULD be flagged as XSS sink
        let content = r#"el.innerHTML += "<div>more</div>";"#;
        let parsed = parse_js(content);
        let rule = InnerHtmlRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "innerHTML augmented assignment should be flagged"
        );
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn test_innerhtml_read_not_flagged_by_xss_rule() {
        // const x = el.innerHTML should NOT be flagged by the XSS rule
        let content = r#"const content = document.body.innerHTML;"#;
        let parsed = parse_js(content);
        let rule = InnerHtmlRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "innerHTML read should not be flagged by XSS rule"
        );
    }

    #[test]
    fn test_innerhtml_read_flagged_by_read_rule() {
        // const x = el.innerHTML SHOULD be flagged by the read rule (Info severity)
        let content = r#"const content = document.body.innerHTML;"#;
        let parsed = parse_js(content);
        let rule = InnerHtmlReadRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "innerHTML read should be flagged by read rule"
        );
        assert_eq!(findings[0].rule_id, "js/innerhtml-read");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_innerhtml_write_not_flagged_by_read_rule() {
        // el.innerHTML = x should NOT be flagged by the read rule
        let content = r#"el.innerHTML = "<div>test</div>";"#;
        let parsed = parse_js(content);
        let rule = InnerHtmlReadRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "innerHTML write should not be flagged by read rule"
        );
    }

    #[test]
    fn test_outerhtml_write_flagged() {
        // el.outerHTML = x SHOULD be flagged as XSS sink
        let content = r#"el.outerHTML = template;"#;
        let parsed = parse_js(content);
        let rule = InnerHtmlRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "outerHTML assignment should be flagged");
        assert!(findings[0].message.contains("outerHTML"));
    }

    #[test]
    fn test_innerhtml_in_function_argument_is_read() {
        // sanitize(el.innerHTML) is a READ, not a write
        let content = r#"const safe = sanitize(el.innerHTML);"#;
        let parsed = parse_js(content);

        let xss_rule = InnerHtmlRule;
        let xss_findings = xss_rule.check(&parsed);
        assert!(
            xss_findings.is_empty(),
            "Function arg should not be XSS sink"
        );

        let read_rule = InnerHtmlReadRule;
        let read_findings = read_rule.check(&parsed);
        assert_eq!(
            read_findings.len(),
            1,
            "Function arg should be flagged as read"
        );
    }

    // =========================================================================
    // New rules tests
    // =========================================================================

    #[test]
    fn test_jsx_script_url_flagged() {
        let content = r#"<a href="javascript:void(0)">Click</a>"#;
        let parsed = parse_js(content);
        let rule = JsxScriptUrlRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "javascript: URL should be flagged");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_debugger_flagged() {
        let content = "function test() { debugger; return 1; }";
        let parsed = parse_js(content);
        let rule = DebuggerStatementRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "debugger should be flagged");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_alert_flagged() {
        let content = r#"alert("Hello!");"#;
        let parsed = parse_js(content);
        let rule = NoAlertRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "alert should be flagged");
    }

    #[test]
    fn test_strict_equality_loose_flagged() {
        let content = "if (x == 5) { foo(); }";
        let parsed = parse_js(content);
        let rule = StrictEqualityRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "== should be flagged");
        assert!(findings[0].message.contains("==="));
    }

    #[test]
    fn test_strict_equality_null_check_allowed() {
        let content = "if (x == null) { return; }";
        let parsed = parse_js(content);
        let rule = StrictEqualityRule;
        let findings = rule.check(&parsed);
        assert!(findings.is_empty(), "== null should not be flagged");
    }

    #[test]
    fn test_condition_assignment_flagged() {
        let content = "if (x = 5) { foo(); }";
        let parsed = parse_js(content);
        let rule = NoConditionAssignRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "Assignment in condition should be flagged"
        );
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn test_condition_assignment_intentional_not_flagged() {
        // Intentional pattern: assignment in parens compared to null
        let content = "while ((match = regex.exec(str)) !== null) { process(match); }";
        let parsed = parse_js(content);
        let rule = NoConditionAssignRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Intentional assignment pattern should not be flagged"
        );
    }

    #[test]
    fn test_ternary_in_jsx_not_flagged() {
        // Ternary expressions in JSX/template literals are intentional, not bugs
        let content = r#"const el = <div className={`px-2 ${isActive ? "active" : ""}`} />;"#;
        let parsed = parse_js(content);
        let rule = NoConditionAssignRule;
        let findings = rule.check(&parsed);
        assert!(findings.is_empty(), "Ternary in JSX should not be flagged");
    }

    #[test]
    fn test_constant_condition_flagged() {
        let content = "if (true) { foo(); }";
        let parsed = parse_js(content);
        let rule = NoConstantConditionRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "Constant condition should be flagged");
    }

    #[test]
    fn test_valid_typeof_invalid_flagged() {
        let content = r#"if (typeof x === "strng") { }"#;
        let parsed = parse_js(content);
        let rule = ValidTypeofRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "Invalid typeof string should be flagged");
    }

    #[test]
    fn test_valid_typeof_valid_ok() {
        let content = r#"if (typeof x === "string") { }"#;
        let parsed = parse_js(content);
        let rule = ValidTypeofRule;
        let findings = rule.check(&parsed);
        assert!(findings.is_empty(), "Valid typeof should not be flagged");
    }

    #[test]
    fn test_valid_typeof_jsx_classname_not_flagged() {
        // JSX className strings should NOT be flagged as invalid typeof comparisons
        // This was a false positive: className="h-3 w-3" was incorrectly flagged
        let content = r#"<X className="h-3 w-3" />"#;
        let parsed = parse_js(content);
        let rule = ValidTypeofRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "JSX className should not be flagged as typeof comparison"
        );
    }

    #[test]
    fn test_valid_typeof_jsx_with_ternary_not_flagged() {
        // JSX with ternary and typeof elsewhere should not false-positive on className
        let content = r#"
            function Component({ activeTab }) {
                return (
                    <div className="border-b px-2">
                        <Tabs value={activeTab} onValueChange={(v) => {
                            setActiveTab(v as typeof activeTab);
                        }}>
                            <TabsList className="h-9 bg-transparent p-0" />
                        </Tabs>
                    </div>
                );
            }
        "#;
        let parsed = parse_js(content);
        let rule = ValidTypeofRule;
        let findings = rule.check(&parsed);
        // Should not flag className strings as invalid typeof comparisons
        let false_positives: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.message.contains("border-b")
                    || f.message.contains("h-9")
                    || f.message.contains("h-3")
            })
            .collect();
        assert!(
            false_positives.is_empty(),
            "Should not flag className strings: {:?}",
            false_positives
        );
    }
}
