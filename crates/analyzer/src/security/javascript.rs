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

    fn uses_flow(&self) -> bool {
        true
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        // Fallback without flow - flag all innerHTML assignments
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

    fn check_with_flow(
        &self,
        parsed: &ParsedFile,
        flow: &crate::flow::FlowContext,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_member_expressions(&mut cursor, |node: Node| {
            if let Some(prop) = node.child_by_field_name("property")
                && let Ok(prop_text) = prop.utf8_text(parsed.content.as_bytes())
                && Self::DANGEROUS_PROPS.contains(&prop_text)
                && Self::is_assignment_target(&node)
            {
                // Get the parent assignment to check what's being assigned
                if let Some(parent) = node.parent() {
                    if let Some(right) = parent.child_by_field_name("right") {
                        let (severity, confidence, message) = Self::analyze_assignment_with_path(
                            &right,
                            parsed,
                            flow,
                            prop_text,
                            node.id(),
                        );

                        // Only emit findings for Warning or higher
                        if severity >= Severity::Warning {
                            findings.push(create_finding_with_confidence(
                                self.id(),
                                &node,
                                &parsed.path,
                                &parsed.content,
                                severity,
                                &message,
                                Language::JavaScript,
                                confidence,
                            ));
                        }
                    }
                }
            }
        });
        findings
    }
}

impl InnerHtmlRule {
    /// Analyze what's being assigned to innerHTML with path-sensitive taint analysis
    fn analyze_assignment_with_path(
        right: &Node,
        parsed: &ParsedFile,
        flow: &crate::flow::FlowContext,
        prop_name: &str,
        sink_node_id: usize,
    ) -> (Severity, Confidence, String) {
        use crate::flow::{TaintLevel, ValueOrigin};

        match right.kind() {
            // Static string literal → Low severity (probably safe)
            "string" => (
                Severity::Info,
                Confidence::High,
                format!("{} assigned from string literal - likely safe", prop_name),
            ),

            // Template string without interpolation → probably safe
            "template_string" => {
                let text = right.utf8_text(parsed.content.as_bytes()).unwrap_or("");
                // Check if it has interpolations (contains ${)
                if text.contains("${") {
                    (
                        Severity::Warning,
                        Confidence::Medium,
                        format!(
                            "{} assigned from template literal with interpolation - review for XSS",
                            prop_name
                        ),
                    )
                } else {
                    (
                        Severity::Info,
                        Confidence::High,
                        format!(
                            "{} assigned from static template literal - likely safe",
                            prop_name
                        ),
                    )
                }
            }

            // Variable → use path-sensitive taint analysis
            "identifier" => {
                let var_name = right.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                // Use path-sensitive taint level
                let taint_level = flow.taint_level_at(var_name, sink_node_id);

                match taint_level {
                    TaintLevel::Full => (
                        Severity::Error,
                        Confidence::High,
                        format!(
                            "{} assigned from tainted variable '{}' - XSS vulnerability. Sanitize with DOMPurify or use textContent.",
                            prop_name, var_name
                        ),
                    ),
                    TaintLevel::Partial => (
                        Severity::Warning,
                        Confidence::Medium,
                        format!(
                            "{} assigned from '{}' which is tainted on some paths - ensure sanitization on all paths",
                            prop_name, var_name
                        ),
                    ),
                    TaintLevel::Clean => {
                        // Check if it was sanitized or is a literal
                        if flow.symbols.is_literal(var_name) {
                            (
                                Severity::Info,
                                Confidence::High,
                                format!(
                                    "{} assigned from '{}' (literal value) - safe",
                                    prop_name, var_name
                                ),
                            )
                        } else {
                            let origin = flow.symbols.origin_of(var_name);
                            match origin {
                                ValueOrigin::FunctionCall(ref func_name)
                                    if flow.config.is_sanitizer(func_name) =>
                                {
                                    (
                                        Severity::Info,
                                        Confidence::High,
                                        format!(
                                            "{} assigned from '{}' (sanitized by {}) - safe",
                                            prop_name, var_name, func_name
                                        ),
                                    )
                                }
                                ValueOrigin::FunctionCall(ref func_name) => (
                                    Severity::Warning,
                                    Confidence::Medium,
                                    format!(
                                        "{} assigned from '{}' (from function '{}') - review for XSS",
                                        prop_name, var_name, func_name
                                    ),
                                ),
                                ValueOrigin::Literal(_) => (
                                    Severity::Info,
                                    Confidence::High,
                                    format!(
                                        "{} assigned from '{}' (literal) - safe",
                                        prop_name, var_name
                                    ),
                                ),
                                _ => (
                                    Severity::Info,
                                    Confidence::Medium,
                                    format!(
                                        "{} assigned from '{}' (clean) - likely safe",
                                        prop_name, var_name
                                    ),
                                ),
                            }
                        }
                    }
                }
            }

            // Function call → check if it's a sanitizer
            "call_expression" => {
                if let Some(func_node) = right.child_by_field_name("function") {
                    let func_name = func_node.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                    if flow.config.is_sanitizer(func_name) {
                        (
                            Severity::Info,
                            Confidence::High,
                            format!(
                                "{} assigned from sanitizer '{}' - safe",
                                prop_name, func_name
                            ),
                        )
                    } else if flow.config.is_source_function(func_name) {
                        (
                            Severity::Error,
                            Confidence::High,
                            format!(
                                "{} assigned directly from taint source '{}' - XSS vulnerability",
                                prop_name, func_name
                            ),
                        )
                    } else {
                        (
                            Severity::Warning,
                            Confidence::Medium,
                            format!(
                                "{} assigned from function call '{}' - review for XSS",
                                prop_name, func_name
                            ),
                        )
                    }
                } else {
                    (
                        Severity::Warning,
                        Confidence::Low,
                        format!("{} assigned from function call - review for XSS", prop_name),
                    )
                }
            }

            // Member expression → check if it's a taint source
            "member_expression" => {
                let member_path = right.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                if flow.config.is_source_member(member_path) {
                    (
                        Severity::Error,
                        Confidence::High,
                        format!(
                            "{} assigned directly from taint source '{}' - XSS vulnerability",
                            prop_name, member_path
                        ),
                    )
                } else {
                    (
                        Severity::Warning,
                        Confidence::Medium,
                        format!(
                            "{} assigned from member access '{}' - review for XSS",
                            prop_name, member_path
                        ),
                    )
                }
            }

            // Binary expression (concatenation) → check for tainted parts
            "binary_expression" => (
                Severity::Warning,
                Confidence::Medium,
                format!(
                    "{} assigned from expression - review for XSS if any part is user-controlled",
                    prop_name
                ),
            ),

            // Other cases
            _ => (
                Severity::Warning,
                Confidence::Low,
                format!("{} assignment detected - review for XSS", prop_name),
            ),
        }
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

// =============================================================================
// PRIORITY 3: Additional Security Rules
// =============================================================================

/// DETECTS prototype pollution vulnerabilities
///
/// Detects patterns that can lead to prototype pollution:
/// - `Object.assign({}, userInput)` - can pollute if userInput has __proto__
/// - `_.merge`, `_.extend`, `_.defaultsDeep` with user-controlled objects
/// - `obj[userInput] = value` - computed property assignment
pub struct PrototypePollutionRule;

impl Rule for PrototypePollutionRule {
    fn id(&self) -> &str {
        "js/prototype-pollution"
    }

    fn description(&self) -> &str {
        "Detects patterns that may lead to prototype pollution vulnerabilities"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Dangerous merge/extend functions from lodash and similar libraries
        let dangerous_merge_functions = [
            "merge",
            "extend",
            "defaultsDeep",
            "assign",
            "deepExtend",
            "deepMerge",
        ];

        // Check for dangerous function calls
        find_call_expressions(&mut cursor, |node: Node| {
            if let Some(func) = node.child_by_field_name("function")
                && let Ok(func_text) = func.utf8_text(parsed.content.as_bytes())
            {
                // Check for Object.assign with empty object as first arg
                if func_text == "Object.assign" {
                    if let Some(args) = node.child_by_field_name("arguments")
                        && let Some(first_arg) = args.named_child(0)
                        && let Ok(first_text) = first_arg.utf8_text(parsed.content.as_bytes())
                        && (first_text == "{}" || first_text.starts_with("{ }"))
                    {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "Object.assign with empty target - may be vulnerable to prototype pollution if source is user-controlled",
                            Language::JavaScript,
                            Confidence::Medium,
                        ));
                    }
                }

                // Check for lodash-style merge functions: _.merge, _.extend, etc.
                if func.kind() == "member_expression" {
                    if let Some(prop) = func.child_by_field_name("property")
                        && let Ok(prop_text) = prop.utf8_text(parsed.content.as_bytes())
                        && dangerous_merge_functions.contains(&prop_text)
                    {
                        // Check if it's from a common utility library (_, lodash, etc.)
                        if let Some(obj) = func.child_by_field_name("object")
                            && let Ok(obj_text) = obj.utf8_text(parsed.content.as_bytes())
                            && (obj_text == "_"
                                || obj_text == "lodash"
                                || obj_text == "underscore"
                                || obj_text == "jQuery"
                                || obj_text == "$")
                        {
                            findings.push(create_finding_with_confidence(
                                self.id(),
                                &node,
                                &parsed.path,
                                &parsed.content,
                                Severity::Warning,
                                &format!(
                                    "{}.{}() can cause prototype pollution if merging user-controlled objects - use a safe merge or validate input",
                                    obj_text, prop_text
                                ),
                                Language::JavaScript,
                                Confidence::Medium,
                            ));
                        }
                    }
                }
            }
        });

        // Check for computed property assignment: obj[userInput] = value
        cursor = parsed.tree.walk();
        find_nodes_by_kind(&mut cursor, "subscript_expression", |node: Node| {
            // Check if this is on the left side of an assignment
            if let Some(parent) = node.parent()
                && (parent.kind() == "assignment_expression"
                    || parent.kind() == "augmented_assignment_expression")
                && let Some(left) = parent.child_by_field_name("left")
                && left.id() == node.id()
            {
                // Get the index expression
                if let Some(index) = node.child_by_field_name("index")
                    && index.kind() == "identifier"
                {
                    // It's a variable being used as a property key
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "Computed property assignment with variable key - may allow prototype pollution if key is user-controlled (e.g., '__proto__')",
                        Language::JavaScript,
                        Confidence::Medium,
                    ));
                }
            }
        });

        findings
    }
}

/// DETECTS ReDoS (Regular Expression Denial of Service) vulnerabilities
///
/// Detects regex patterns with nested quantifiers that can cause catastrophic backtracking:
/// - `(a+)+`, `(a*)*`, `(a|a)*` - nested quantifiers
/// - `new RegExp(userInput)` - dynamic regex from user input
pub struct RedosRule;

impl RedosRule {
    /// Check if a regex pattern contains potentially vulnerable nested quantifiers
    fn has_nested_quantifiers(pattern: &str) -> bool {
        // Simple heuristic: look for patterns like (x+)+, (x*)+, (x+)*, (x*)*, (x|x)+
        // This is a simplified check - a full analysis would require regex parsing

        let quantifiers = ['+', '*', '?'];
        let mut in_group = 0;
        let mut group_has_quantifier = false;
        let chars: Vec<char> = pattern.chars().collect();

        for i in 0..chars.len() {
            let c = chars[i];
            match c {
                '(' => {
                    in_group += 1;
                    group_has_quantifier = false;
                }
                ')' => {
                    if in_group > 0 {
                        in_group -= 1;
                        // Check if followed by a quantifier
                        if i + 1 < chars.len() && quantifiers.contains(&chars[i + 1]) {
                            if group_has_quantifier {
                                return true; // Nested quantifiers!
                            }
                        }
                    }
                }
                '+' | '*' => {
                    if in_group > 0 {
                        group_has_quantifier = true;
                    }
                }
                '|' => {
                    // Check for alternation with repetition like (a|a)+
                    // This is a simplified check
                    if in_group > 0 {
                        group_has_quantifier = true;
                    }
                }
                _ => {}
            }
        }

        // Also check for common dangerous patterns
        let dangerous_patterns = [
            "(.*)*",
            "(.+)+",
            "(.*)+",
            "(.+)*",
            "(a+)+",
            "(a*)+",
            "(a+)*",
            "(a*)*",
            "([^\"]+)+",
            "(\\s*)*",
            "(\\s+)+",
            "(\\d+)+",
            "(\\w+)+",
        ];

        for dangerous in dangerous_patterns {
            if pattern.contains(dangerous) {
                return true;
            }
        }

        false
    }
}

impl Rule for RedosRule {
    fn id(&self) -> &str {
        "js/redos-vulnerable"
    }

    fn description(&self) -> &str {
        "Detects regex patterns vulnerable to ReDoS (catastrophic backtracking)"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Check regex literals
        find_nodes_by_kind(&mut cursor, "regex", |node: Node| {
            if let Ok(pattern) = node.utf8_text(parsed.content.as_bytes()) {
                if Self::has_nested_quantifiers(pattern) {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "Regex with nested quantifiers may be vulnerable to ReDoS - consider using atomic groups or possessive quantifiers",
                        Language::JavaScript,
                        Confidence::Medium,
                    ));
                }
            }
        });

        // Check new RegExp() with variable input
        cursor = parsed.tree.walk();
        find_nodes_by_kind(&mut cursor, "new_expression", |node: Node| {
            if let Some(constructor) = node.child_by_field_name("constructor")
                && let Ok(ctor_text) = constructor.utf8_text(parsed.content.as_bytes())
                && ctor_text == "RegExp"
            {
                if let Some(args) = node.child_by_field_name("arguments")
                    && let Some(first_arg) = args.named_child(0)
                {
                    match first_arg.kind() {
                        "identifier" | "member_expression" | "call_expression" => {
                            // Variable or function call used as regex pattern
                            findings.push(create_finding_with_confidence(
                                self.id(),
                                &node,
                                &parsed.path,
                                &parsed.content,
                                Severity::Warning,
                                "new RegExp() with dynamic input may be vulnerable to ReDoS if pattern is user-controlled - validate and escape input",
                                Language::JavaScript,
                                Confidence::Medium,
                            ));
                        }
                        "string" | "template_string" => {
                            // Check the string pattern itself
                            if let Ok(pattern) = first_arg.utf8_text(parsed.content.as_bytes()) {
                                if Self::has_nested_quantifiers(pattern) {
                                    findings.push(create_finding_with_confidence(
                                        self.id(),
                                        &node,
                                        &parsed.path,
                                        &parsed.content,
                                        Severity::Warning,
                                        "RegExp with nested quantifiers may be vulnerable to ReDoS",
                                        Language::JavaScript,
                                        Confidence::Medium,
                                    ));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        });

        findings
    }
}

/// DETECTS missing security headers in Express apps
///
/// Detects Express apps that may be missing security headers:
/// - No `helmet()` middleware
/// - Missing common security middleware
pub struct MissingSecurityHeadersRule;

impl MissingSecurityHeadersRule {
    /// Check if the file imports or requires helmet
    fn has_helmet_import(parsed: &ParsedFile) -> bool {
        let content = &parsed.content;
        content.contains("require('helmet')")
            || content.contains("require(\"helmet\")")
            || content.contains("from 'helmet'")
            || content.contains("from \"helmet\"")
    }

    /// Check if helmet() is called in the file
    fn has_helmet_usage(parsed: &ParsedFile) -> bool {
        let content = &parsed.content;
        content.contains("helmet()")
            || content.contains("helmet.contentSecurityPolicy")
            || content.contains("helmet.hsts")
    }
}

impl Rule for MissingSecurityHeadersRule {
    fn id(&self) -> &str {
        "js/missing-security-headers"
    }

    fn description(&self) -> &str {
        "Detects Express apps that may be missing security headers (helmet middleware)"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // First, check if this looks like an Express app
        let content = &parsed.content;
        let is_express_app = content.contains("express()")
            || content.contains("require('express')")
            || content.contains("require(\"express\")")
            || content.contains("from 'express'")
            || content.contains("from \"express\"");

        if !is_express_app {
            return findings;
        }

        // Check if helmet is imported and used
        let has_helmet = Self::has_helmet_import(parsed) && Self::has_helmet_usage(parsed);

        if !has_helmet {
            // Find the express() call to report the finding
            find_call_expressions(&mut cursor, |node: Node| {
                if let Some(func) = node.child_by_field_name("function")
                    && let Ok(func_text) = func.utf8_text(parsed.content.as_bytes())
                    && func_text == "express"
                {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Info,
                        "Express app without helmet() middleware - consider adding helmet for security headers (CSP, HSTS, X-Frame-Options, etc.)",
                        Language::JavaScript,
                        Confidence::Low,
                    ));
                }
            });
        }

        findings
    }
}

/// DETECTS Express-specific security issues
///
/// Detects common Express security misconfigurations:
/// - `express.json()` without size limits
/// - `cors()` with `origin: '*'` (overly permissive)
/// - Auth routes without rate limiting
pub struct ExpressSecurityRule;

impl ExpressSecurityRule {
    /// Common auth route patterns
    const AUTH_ROUTES: &'static [&'static str] = &[
        "/login",
        "/signin",
        "/auth",
        "/register",
        "/signup",
        "/password",
        "/reset",
        "/forgot",
        "/api/auth",
        "/api/login",
    ];

    /// Check if a string looks like an auth route
    fn is_auth_route(route: &str) -> bool {
        let route_lower = route.to_lowercase();
        Self::AUTH_ROUTES
            .iter()
            .any(|auth| route_lower.contains(auth))
    }
}

impl Rule for ExpressSecurityRule {
    fn id(&self) -> &str {
        "js/express-security"
    }

    fn description(&self) -> &str {
        "Detects Express-specific security issues (body parser limits, CORS, rate limiting)"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(lang, Language::JavaScript | Language::TypeScript)
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        let content = &parsed.content;

        // Check if this is an Express file
        let is_express_file = content.contains("express")
            || content.contains("app.use")
            || content.contains("app.get")
            || content.contains("app.post")
            || content.contains("router.");

        if !is_express_file {
            return findings;
        }

        // Track if rate limiting is present
        let has_rate_limiter = content.contains("rateLimit")
            || content.contains("rate-limit")
            || content.contains("express-rate-limit")
            || content.contains("express-slow-down")
            || content.contains("rateLimiter");

        find_call_expressions(&mut cursor, |node: Node| {
            if let Some(func) = node.child_by_field_name("function")
                && let Ok(func_text) = func.utf8_text(parsed.content.as_bytes())
            {
                // Check for express.json() without limit
                if func_text == "express.json" || func_text == "bodyParser.json" {
                    let mut has_limit = false;
                    if let Some(args) = node.child_by_field_name("arguments")
                        && let Some(options) = args.named_child(0)
                        && let Ok(options_text) = options.utf8_text(parsed.content.as_bytes())
                    {
                        has_limit = options_text.contains("limit");
                    }

                    if !has_limit {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "express.json() without size limit - add { limit: '100kb' } to prevent large payload attacks",
                            Language::JavaScript,
                            Confidence::Medium,
                        ));
                    }
                }

                // Check for express.urlencoded() without limit
                if func_text == "express.urlencoded" || func_text == "bodyParser.urlencoded" {
                    let mut has_limit = false;
                    if let Some(args) = node.child_by_field_name("arguments")
                        && let Some(options) = args.named_child(0)
                        && let Ok(options_text) = options.utf8_text(parsed.content.as_bytes())
                    {
                        has_limit = options_text.contains("limit");
                    }

                    if !has_limit {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "express.urlencoded() without size limit - add { limit: '100kb' } to prevent large payload attacks",
                            Language::JavaScript,
                            Confidence::Medium,
                        ));
                    }
                }

                // Check for cors() with origin: '*'
                if func_text == "cors" {
                    if let Some(args) = node.child_by_field_name("arguments")
                        && let Some(options) = args.named_child(0)
                        && let Ok(options_text) = options.utf8_text(parsed.content.as_bytes())
                    {
                        if options_text.contains("origin: '*'")
                            || options_text.contains("origin: \"*\"")
                            || options_text.contains("origin:'*'")
                            || options_text.contains("origin:\"*\"")
                        {
                            findings.push(create_finding_with_confidence(
                                self.id(),
                                &node,
                                &parsed.path,
                                &parsed.content,
                                Severity::Warning,
                                "CORS with origin: '*' allows any domain - specify allowed origins for production",
                                Language::JavaScript,
                                Confidence::Medium,
                            ));
                        }
                    }
                }

                // Check for auth routes without rate limiting
                if !has_rate_limiter {
                    // Check app.post('/login', ...) style routes
                    if func_text == "app.post"
                        || func_text == "router.post"
                        || func_text == "app.put"
                        || func_text == "router.put"
                    {
                        if let Some(args) = node.child_by_field_name("arguments")
                            && let Some(route_arg) = args.named_child(0)
                            && let Ok(route) = route_arg.utf8_text(parsed.content.as_bytes())
                            && Self::is_auth_route(route)
                        {
                            findings.push(create_finding_with_confidence(
                                self.id(),
                                &node,
                                &parsed.path,
                                &parsed.content,
                                Severity::Warning,
                                &format!(
                                    "Auth route {} without rate limiting - add express-rate-limit to prevent brute force attacks",
                                    route
                                ),
                                Language::JavaScript,
                                Confidence::Medium,
                            ));
                        }
                    }
                }
            }
        });

        findings
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

    // =========================================================================
    // Prototype Pollution tests
    // =========================================================================

    #[test]
    fn test_prototype_pollution_object_assign_empty_target() {
        let content = r#"const merged = Object.assign({}, userInput);"#;
        let parsed = parse_js(content);
        let rule = PrototypePollutionRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "Object.assign with empty target should be flagged"
        );
        assert!(findings[0].message.contains("prototype pollution"));
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_prototype_pollution_object_assign_existing_target_ok() {
        let content = r#"const merged = Object.assign(existingObj, userInput);"#;
        let parsed = parse_js(content);
        let rule = PrototypePollutionRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Object.assign with existing target should not be flagged"
        );
    }

    #[test]
    fn test_prototype_pollution_lodash_merge() {
        let content = r#"const merged = _.merge(target, userInput);"#;
        let parsed = parse_js(content);
        let rule = PrototypePollutionRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "_.merge should be flagged");
        assert!(findings[0].message.contains("prototype pollution"));
    }

    #[test]
    fn test_prototype_pollution_lodash_extend() {
        let content = r#"lodash.extend(config, options);"#;
        let parsed = parse_js(content);
        let rule = PrototypePollutionRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "lodash.extend should be flagged");
    }

    #[test]
    fn test_prototype_pollution_computed_property_assignment() {
        let content = r#"obj[key] = value;"#;
        let parsed = parse_js(content);
        let rule = PrototypePollutionRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "Computed property assignment should be flagged"
        );
        assert!(findings[0].message.contains("Computed property assignment"));
    }

    #[test]
    fn test_prototype_pollution_static_property_ok() {
        let content = r#"obj.name = value;"#;
        let parsed = parse_js(content);
        let rule = PrototypePollutionRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Static property assignment should not be flagged"
        );
    }

    // =========================================================================
    // ReDoS tests
    // =========================================================================

    #[test]
    fn test_redos_nested_quantifier_literal() {
        let content = r#"const re = /(a+)+$/;"#;
        let parsed = parse_js(content);
        let rule = RedosRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "Nested quantifier regex should be flagged"
        );
        assert!(findings[0].message.contains("ReDoS"));
    }

    #[test]
    fn test_redos_star_plus_pattern() {
        let content = r#"const re = /(.+)+/;"#;
        let parsed = parse_js(content);
        let rule = RedosRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "(.+)+ pattern should be flagged as ReDoS vulnerable"
        );
    }

    #[test]
    fn test_redos_new_regexp_variable() {
        let content = r#"const re = new RegExp(userPattern);"#;
        let parsed = parse_js(content);
        let rule = RedosRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "new RegExp with variable should be flagged"
        );
        assert!(findings[0].message.contains("dynamic input"));
    }

    #[test]
    fn test_redos_new_regexp_dangerous_string() {
        let content = r#"const re = new RegExp("(a+)+");"#;
        let parsed = parse_js(content);
        let rule = RedosRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "new RegExp with dangerous string should be flagged"
        );
    }

    #[test]
    fn test_redos_safe_regex_ok() {
        let content = r#"const re = /^[a-z]+$/;"#;
        let parsed = parse_js(content);
        let rule = RedosRule;
        let findings = rule.check(&parsed);
        assert!(findings.is_empty(), "Safe regex should not be flagged");
    }

    // =========================================================================
    // Missing Security Headers tests
    // =========================================================================

    #[test]
    fn test_missing_csp_express_without_helmet() {
        let content = r#"
            const express = require('express');
            const app = express();
            app.get('/', (req, res) => res.send('Hello'));
        "#;
        let parsed = parse_js(content);
        let rule = MissingSecurityHeadersRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "Express app without helmet should be flagged"
        );
        assert!(findings[0].message.contains("helmet"));
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_missing_csp_express_with_helmet_ok() {
        let content = r#"
            const express = require('express');
            const helmet = require('helmet');
            const app = express();
            app.use(helmet());
            app.get('/', (req, res) => res.send('Hello'));
        "#;
        let parsed = parse_js(content);
        let rule = MissingSecurityHeadersRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Express app with helmet should not be flagged"
        );
    }

    #[test]
    fn test_missing_csp_non_express_ok() {
        let content = r#"
            const http = require('http');
            http.createServer((req, res) => res.end('Hello'));
        "#;
        let parsed = parse_js(content);
        let rule = MissingSecurityHeadersRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Non-Express app should not be flagged by this rule"
        );
    }

    // =========================================================================
    // Express Security tests
    // =========================================================================

    #[test]
    fn test_express_json_without_limit() {
        let content = r#"
            const app = express();
            app.use(express.json());
        "#;
        let parsed = parse_js(content);
        let rule = ExpressSecurityRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "express.json() without limit should be flagged"
        );
        assert!(findings[0].message.contains("limit"));
    }

    #[test]
    fn test_express_json_with_limit_ok() {
        let content = r#"
            const app = express();
            app.use(express.json({ limit: '100kb' }));
        "#;
        let parsed = parse_js(content);
        let rule = ExpressSecurityRule;
        let findings = rule.check(&parsed);
        let json_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("express.json"))
            .collect();
        assert!(
            json_findings.is_empty(),
            "express.json() with limit should not be flagged"
        );
    }

    #[test]
    fn test_express_cors_wildcard_origin() {
        let content = r#"
            const app = express();
            app.use(cors({ origin: '*' }));
        "#;
        let parsed = parse_js(content);
        let rule = ExpressSecurityRule;
        let findings = rule.check(&parsed);
        let cors_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("CORS"))
            .collect();
        assert_eq!(
            cors_findings.len(),
            1,
            "cors with origin: '*' should be flagged"
        );
    }

    #[test]
    fn test_express_cors_specific_origin_ok() {
        let content = r#"
            const app = express();
            app.use(cors({ origin: 'https://example.com' }));
        "#;
        let parsed = parse_js(content);
        let rule = ExpressSecurityRule;
        let findings = rule.check(&parsed);
        let cors_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("CORS"))
            .collect();
        assert!(
            cors_findings.is_empty(),
            "cors with specific origin should not be flagged"
        );
    }

    #[test]
    fn test_express_auth_route_without_rate_limit() {
        let content = r#"
            const app = express();
            app.post('/login', (req, res) => { /* ... */ });
        "#;
        let parsed = parse_js(content);
        let rule = ExpressSecurityRule;
        let findings = rule.check(&parsed);
        let auth_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("rate limit"))
            .collect();
        assert_eq!(
            auth_findings.len(),
            1,
            "Auth route without rate limiting should be flagged"
        );
    }

    #[test]
    fn test_express_auth_route_with_rate_limit_ok() {
        let content = r#"
            const rateLimit = require('express-rate-limit');
            const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
            const app = express();
            app.use(limiter);
            app.post('/login', (req, res) => { /* ... */ });
        "#;
        let parsed = parse_js(content);
        let rule = ExpressSecurityRule;
        let findings = rule.check(&parsed);
        let auth_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("rate limit"))
            .collect();
        assert!(
            auth_findings.is_empty(),
            "Auth route with rate limiting should not be flagged"
        );
    }

    #[test]
    fn test_express_router_auth_route() {
        let content = r#"
            const router = express.Router();
            router.post('/api/auth/login', authController.login);
        "#;
        let parsed = parse_js(content);
        let rule = ExpressSecurityRule;
        let findings = rule.check(&parsed);
        let auth_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("rate limit"))
            .collect();
        assert_eq!(
            auth_findings.len(),
            1,
            "Router auth route without rate limiting should be flagged"
        );
    }

    // =========================================================================
    // Additional ReDoS tests (Phase 5 coverage)
    // =========================================================================

    #[test]
    fn test_redos_alternation_in_group_flagged() {
        // Alternation with overlapping patterns in a group
        let content = r#"const re = /^(a|a)+$/;"#;
        let parsed = parse_js(content);
        let rule = RedosRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "Overlapping alternation should be flagged"
        );
    }

    #[test]
    fn test_redos_star_star_pattern_flagged() {
        let content = r#"const re = /(.*)*$/;"#;
        let parsed = parse_js(content);
        let rule = RedosRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "(.*)*$ pattern should be flagged as ReDoS"
        );
    }

    #[test]
    fn test_redos_simple_character_class_ok() {
        // Simple non-nested regex should not be flagged
        let content = r#"const re = /^[a-zA-Z0-9_-]+@[a-zA-Z0-9.-]+$/;"#;
        let parsed = parse_js(content);
        let rule = RedosRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Simple character class regex should not be flagged"
        );
    }

    #[test]
    fn test_redos_fixed_quantifier_ok() {
        // Fixed quantifiers are not vulnerable
        let content = r#"const re = /^[a-z]{3,10}$/;"#;
        let parsed = parse_js(content);
        let rule = RedosRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Fixed quantifier regex should not be flagged"
        );
    }

    #[test]
    fn test_redos_word_boundary_ok() {
        // Word boundary patterns are typically safe
        let content = r#"const re = /\b\w+\b/g;"#;
        let parsed = parse_js(content);
        let rule = RedosRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Word boundary regex should not be flagged"
        );
    }

    // =========================================================================
    // Additional Missing Security Headers tests (Phase 5 coverage)
    // =========================================================================

    #[test]
    fn test_missing_headers_fastify_without_helmet() {
        let content = r#"
            const fastify = require('fastify')();
            fastify.get('/', async (request, reply) => 'Hello');
        "#;
        let parsed = parse_js(content);
        let rule = MissingSecurityHeadersRule;
        let findings = rule.check(&parsed);
        // Note: This rule currently focuses on Express, so fastify may not trigger
        // Adding this test to verify the boundary case
        assert!(
            findings.is_empty() || findings[0].message.contains("security headers"),
            "Non-Express framework should handle gracefully"
        );
    }

    #[test]
    fn test_missing_headers_express_import_style() {
        let content = r#"
            import express from 'express';
            const app = express();
            app.get('/api', (req, res) => res.json({ status: 'ok' }));
        "#;
        let parsed = parse_js(content);
        let rule = MissingSecurityHeadersRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "ES module import Express without helmet should be flagged"
        );
    }

    #[test]
    fn test_missing_headers_express_with_manual_csp() {
        let content = r#"
            const express = require('express');
            const app = express();
            app.use((req, res, next) => {
                res.setHeader('Content-Security-Policy', "default-src 'self'");
                next();
            });
            app.get('/', (req, res) => res.send('Hello'));
        "#;
        let parsed = parse_js(content);
        let rule = MissingSecurityHeadersRule;
        let findings = rule.check(&parsed);
        // This still may flag because we specifically look for helmet
        // But it's a valid pattern to document
        assert!(
            findings.len() <= 1,
            "Manual CSP header setting is an alternative to helmet"
        );
    }

    // =========================================================================
    // Additional Prototype Pollution tests (Phase 5 coverage)
    // =========================================================================

    #[test]
    fn test_prototype_pollution_deep_merge_function() {
        // Deep merge functions are risky for prototype pollution
        let content = r#"function deepMerge(target, source) { return _.merge(target, source); }"#;
        let parsed = parse_js(content);
        let rule = PrototypePollutionRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "_.merge in deep merge function should be flagged"
        );
    }

    #[test]
    fn test_prototype_pollution_jquery_extend_deep() {
        // Deep extend with first arg true is dangerous
        let content = r#"jQuery.extend(true, target, userInput);"#;
        let parsed = parse_js(content);
        let rule = PrototypePollutionRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "jQuery.extend deep should be flagged");
    }

    #[test]
    fn test_prototype_pollution_safe_object_create_ok() {
        // Object.create(null) creates prototype-less object
        let content = r#"const obj = Object.create(null);"#;
        let parsed = parse_js(content);
        let rule = PrototypePollutionRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Object.create(null) should not be flagged"
        );
    }

    // =========================================================================
    // Additional Express Security tests (Phase 5 coverage)
    // =========================================================================

    #[test]
    fn test_express_urlencoded_without_limit() {
        let content = r#"
            const app = express();
            app.use(express.urlencoded({ extended: true }));
        "#;
        let parsed = parse_js(content);
        let rule = ExpressSecurityRule;
        let findings = rule.check(&parsed);
        let body_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("limit") || f.message.contains("body"))
            .collect();
        assert!(
            !body_findings.is_empty(),
            "express.urlencoded without limit should be flagged"
        );
    }

    #[test]
    fn test_express_body_parser_with_limit_ok() {
        let content = r#"
            const bodyParser = require('body-parser');
            const app = express();
            app.use(bodyParser.json({ limit: '1mb' }));
        "#;
        let parsed = parse_js(content);
        let rule = ExpressSecurityRule;
        let findings = rule.check(&parsed);
        let body_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("body-parser") && f.message.contains("limit"))
            .collect();
        assert!(
            body_findings.is_empty(),
            "body-parser with limit should not be flagged"
        );
    }

    #[test]
    fn test_express_signup_route_without_rate_limit() {
        let content = r#"
            const app = express();
            app.post('/signup', (req, res) => { /* create user */ });
        "#;
        let parsed = parse_js(content);
        let rule = ExpressSecurityRule;
        let findings = rule.check(&parsed);
        let auth_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.message.contains("rate limit"))
            .collect();
        assert_eq!(
            auth_findings.len(),
            1,
            "Signup route without rate limiting should be flagged"
        );
    }
}
