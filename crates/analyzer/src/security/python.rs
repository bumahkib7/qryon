//! Python-specific security vulnerability DETECTION rules
//!
//! This module contains STATIC ANALYSIS rules that scan Python source code
//! to identify potential security vulnerabilities. It does NOT execute any code.

use crate::rules::{Rule, create_finding};
use rma_common::{Finding, Language, Severity};
use rma_parser::ParsedFile;
use tree_sitter::Node;

/// DETECTS dangerous dynamic code execution patterns via AST scanning
pub struct DynamicExecutionRule;

impl Rule for DynamicExecutionRule {
    fn id(&self) -> &str {
        "python/dynamic-execution"
    }

    fn description(&self) -> &str {
        "Scans AST to detect dangerous dynamic code execution patterns"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Static list of function names to flag during AST analysis
        let flagged_builtins = ["exec", "compile", "__import__"];

        find_calls(&mut cursor, |node: Node| {
            if let Some(func) = node.child_by_field_name("function")
                && let Ok(text) = func.utf8_text(parsed.content.as_bytes())
                && flagged_builtins.contains(&text)
            {
                findings.push(create_finding(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Critical,
                    &format!(
                        "AST detected {} call - review for code injection risk",
                        text
                    ),
                    Language::Python,
                ));
            }
        });
        findings
    }
}

/// DETECTS potential shell command injection via static pattern matching
pub struct ShellInjectionRule;

impl Rule for ShellInjectionRule {
    fn id(&self) -> &str {
        "python/shell-injection"
    }

    fn description(&self) -> &str {
        "Scans for subprocess patterns with shell=True that may be vulnerable"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_calls(&mut cursor, |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Static pattern matching on AST text - not execution
                let has_shell_true = text.contains("subprocess") && text.contains("shell=True");
                let has_risky_module_call = text.contains("popen(");

                if has_shell_true || has_risky_module_call {
                    findings.push(create_finding(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Critical,
                        "Shell command execution pattern detected - review for injection risk",
                        Language::Python,
                    ));
                }
            }
        });
        findings
    }
}

/// DETECTS hardcoded secrets and credentials via pattern matching
pub struct HardcodedSecretRule;

impl Rule for HardcodedSecretRule {
    fn id(&self) -> &str {
        "python/hardcoded-secret"
    }

    fn description(&self) -> &str {
        "Scans variable names for potential hardcoded secrets"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        let secret_keywords = [
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "auth_token",
            "private_key",
        ];

        find_assignments(&mut cursor, |node: Node| {
            if let Some(left) = node.child_by_field_name("left")
                && let Ok(var_name) = left.utf8_text(parsed.content.as_bytes())
            {
                let var_lower = var_name.to_lowercase();
                for keyword in &secret_keywords {
                    if var_lower.contains(keyword)
                        && let Some(right) = node.child_by_field_name("right")
                        && right.kind() == "string"
                    {
                        findings.push(create_finding(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Critical,
                            "Hardcoded credential pattern detected - use env vars",
                            Language::Python,
                        ));
                        break;
                    }
                }
            }
        });
        findings
    }
}

fn find_calls<F>(cursor: &mut tree_sitter::TreeCursor, mut callback: F)
where
    F: FnMut(Node),
{
    loop {
        let node = cursor.node();
        if node.kind() == "call" {
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

fn find_assignments<F>(cursor: &mut tree_sitter::TreeCursor, mut callback: F)
where
    F: FnMut(Node),
{
    loop {
        let node = cursor.node();
        if node.kind() == "assignment" || node.kind() == "expression_statement" {
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
