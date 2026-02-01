//! Go-specific security vulnerability DETECTION rules
//!
//! Optimized for speed with:
//! - Single-pass AST traversal where possible
//! - Pre-compiled patterns with LazyLock
//! - HashSet for O(1) lookups
//! - No unnecessary allocations
//!
//! Categorized into:
//! - **Sinks (High Confidence)**: Precise detection of dangerous patterns
//! - **Review Hints (Low Confidence)**: Patterns that need human review

use crate::rules::{Rule, create_finding_with_confidence};
use crate::security::generic::{is_generated_file, is_test_or_fixture_file};
use regex::Regex;
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use std::collections::HashSet;
use std::sync::LazyLock;
use tree_sitter::Node;

// =============================================================================
// PRE-COMPILED PATTERNS (initialized once, reused)
// =============================================================================

/// Hardcoded credential patterns
static CREDENTIAL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(password|passwd|secret|api_?key|auth_?token|access_?token)\s*[:=]\s*["'][^"']{8,}["']"#).unwrap()
});

/// AWS-style keys
static AWS_KEY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap());

/// Weak hash functions
static WEAK_HASH_IMPORTS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    ["crypto/md5", "crypto/sha1", "crypto/des", "crypto/rc4"]
        .into_iter()
        .collect()
});

/// Case-insensitive substring search without allocation
#[inline]
fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

// =============================================================================
// MULTI-RULE SCANNER (Single AST pass for maximum speed)
// =============================================================================

/// Fast multi-rule scanner that checks all Go security rules in a single AST pass
pub struct GoSecurityScanner;

impl Rule for GoSecurityScanner {
    fn id(&self) -> &str {
        "go/security-scanner"
    }

    fn description(&self) -> &str {
        "Fast multi-rule Go security scanner (single AST pass)"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Quick content checks to skip files that don't need detailed scanning
        let has_sql = parsed.content.contains("database/sql") || parsed.content.contains("\"sql\"");
        let has_exec = parsed.content.contains("os/exec");
        let has_http = parsed.content.contains("net/http");
        let has_unsafe = parsed.content.contains("\"unsafe\"");
        let has_crypto = parsed.content.contains("crypto/");
        let has_filepath = parsed.content.contains("filepath") || parsed.content.contains("path/");

        // Skip unsafe pointer checks for generated files (e.g., Kubernetes zz_generated_*)
        // These files use unsafe.Pointer intentionally for performance-critical conversions
        let skip_unsafe_check = is_generated_file(&parsed.path, &parsed.content);

        // Line-based checks (credentials, weak crypto imports)
        self.check_lines(parsed, &mut findings, has_crypto);

        // AST-based checks (single traversal)
        let mut cursor = parsed.tree.walk();
        self.traverse_ast(
            &mut cursor,
            parsed,
            &mut findings,
            has_sql,
            has_exec,
            has_http,
            has_unsafe && !skip_unsafe_check, // Skip unsafe check for generated files
            has_filepath,
        );

        findings
    }
}

impl GoSecurityScanner {
    /// Check lines for patterns (credentials, imports)
    fn check_lines(&self, parsed: &ParsedFile, findings: &mut Vec<Finding>, has_crypto: bool) {
        // Skip credential checks in test/fixture files - they commonly contain fake secrets
        if is_test_or_fixture_file(&parsed.path) {
            return;
        }

        for (line_num, line) in parsed.content.lines().enumerate() {
            // Hardcoded credentials
            if CREDENTIAL_PATTERN.is_match(line) {
                findings.push(create_line_based_finding(
                    "go/hardcoded-credential",
                    line_num + 1,
                    1,
                    &parsed.path,
                    line,
                    Severity::Critical,
                    "Hardcoded credential detected - use environment variables or secret management",
                    Language::Go,
                    Confidence::High,
                ));
            }

            // AWS keys
            if AWS_KEY_PATTERN.is_match(line) {
                findings.push(create_line_based_finding(
                    "go/aws-key-exposed",
                    line_num + 1,
                    1,
                    &parsed.path,
                    line,
                    Severity::Critical,
                    "AWS access key detected - rotate immediately and use IAM roles",
                    Language::Go,
                    Confidence::High,
                ));
            }

            // Weak crypto imports
            if has_crypto && line.contains("import") {
                for weak in WEAK_HASH_IMPORTS.iter() {
                    if line.contains(weak) {
                        findings.push(create_line_based_finding(
                            "go/weak-crypto",
                            line_num + 1,
                            1,
                            &parsed.path,
                            line,
                            Severity::Warning,
                            &format!(
                                "Weak crypto import: {} - use crypto/sha256 or stronger",
                                weak
                            ),
                            Language::Go,
                            Confidence::High,
                        ));
                    }
                }
            }
        }
    }

    /// Single-pass AST traversal checking multiple patterns
    #[allow(clippy::too_many_arguments)]
    fn traverse_ast(
        &self,
        cursor: &mut tree_sitter::TreeCursor,
        parsed: &ParsedFile,
        findings: &mut Vec<Finding>,
        has_sql: bool,
        has_exec: bool,
        has_http: bool,
        has_unsafe: bool,
        has_filepath: bool,
    ) {
        loop {
            let node = cursor.node();
            let kind = node.kind();

            match kind {
                "call_expression" => {
                    self.check_call_expression(
                        &node,
                        parsed,
                        findings,
                        has_sql,
                        has_exec,
                        has_http,
                        has_unsafe,
                        has_filepath,
                    );
                }
                "type_conversion_expression" if has_unsafe => {
                    self.check_type_conversion(&node, parsed, findings);
                }
                "short_var_declaration" => {
                    self.check_ignored_error(&node, parsed, findings);
                }
                _ => {}
            }

            // DFS traversal
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

    /// Check call expressions for security issues
    #[allow(clippy::too_many_arguments)]
    fn check_call_expression(
        &self,
        node: &Node,
        parsed: &ParsedFile,
        findings: &mut Vec<Finding>,
        has_sql: bool,
        has_exec: bool,
        has_http: bool,
        has_unsafe: bool,
        has_filepath: bool,
    ) {
        let func = match node.child_by_field_name("function") {
            Some(f) => f,
            None => return,
        };
        let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

        // Command injection
        if has_exec && (func_text.ends_with("exec.Command") || func_text == "Command") {
            self.check_command_injection(node, parsed, findings);
        }

        // SQL injection
        if has_sql && contains_ignore_case(func_text, "sprintf") {
            self.check_sql_injection(node, parsed, findings);
        }

        // Unsafe pointer
        if has_unsafe && func_text.contains("unsafe.Pointer") {
            findings.push(create_finding_with_confidence(
                "go/unsafe-pointer",
                node,
                &parsed.path,
                &parsed.content,
                Severity::Warning,
                "unsafe.Pointer bypasses Go's type safety - ensure this is necessary",
                Language::Go,
                Confidence::High,
            ));
        }

        // Insecure HTTP server
        if has_http && func_text.ends_with("ListenAndServe") && !func_text.contains("TLS") {
            findings.push(create_finding_with_confidence(
                "go/insecure-http",
                node,
                &parsed.path,
                &parsed.content,
                Severity::Warning,
                "HTTP server without TLS - use ListenAndServeTLS for production",
                Language::Go,
                Confidence::High,
            ));
        }

        // SSRF check - http.Get/Post with variable
        if has_http
            && (func_text.ends_with("http.Get") || func_text.ends_with("http.Post"))
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let args_text = args.utf8_text(parsed.content.as_bytes()).unwrap_or("");
            // Check if URL is a variable (not a string literal)
            if !args_text.starts_with("(\"") && !args_text.contains("\"http") {
                findings.push(create_finding_with_confidence(
                    "go/ssrf",
                    node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "HTTP request with variable URL - validate URL to prevent SSRF",
                    Language::Go,
                    Confidence::Medium,
                ));
            }
        }

        // Path traversal
        if has_filepath
            && (func_text.contains("filepath.Join")
                || func_text.contains("os.Open")
                || func_text.contains("ioutil.ReadFile"))
            && let Some(args) = node.child_by_field_name("arguments")
        {
            let args_text = args.utf8_text(parsed.content.as_bytes()).unwrap_or("");
            // Check for user input patterns
            if args_text.contains("request")
                || args_text.contains("param")
                || args_text.contains("input")
            {
                findings.push(create_finding_with_confidence(
                    "go/path-traversal",
                    node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "File operation with user input - validate path to prevent traversal",
                    Language::Go,
                    Confidence::Medium,
                ));
            }
        }

        // Weak crypto usage
        if func_text.contains("md5.") || func_text.contains("sha1.") {
            findings.push(create_finding_with_confidence(
                "go/weak-hash",
                node,
                &parsed.path,
                &parsed.content,
                Severity::Warning,
                "Weak hash function - use sha256 or stronger for security",
                Language::Go,
                Confidence::High,
            ));
        }
    }

    /// Check for command injection patterns
    fn check_command_injection(
        &self,
        node: &Node,
        parsed: &ParsedFile,
        findings: &mut Vec<Finding>,
    ) {
        let args = match node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };
        let args_text = args.utf8_text(parsed.content.as_bytes()).unwrap_or("");

        let is_shell = args_text.contains("\"sh\"")
            || args_text.contains("\"bash\"")
            || args_text.contains("\"/bin/sh\"")
            || args_text.contains("\"/bin/bash\"");

        let has_shell_mode = args_text.contains("\"-c\"");

        if is_shell && has_shell_mode {
            // Check for dynamic arguments
            let context_start = node.start_byte().saturating_sub(500);
            let context_end = (node.end_byte() + 300).min(parsed.content.len());
            let context = &parsed.content[context_start..context_end];

            let has_dynamic = context.contains("fmt.Sprintf")
                || context.contains("+ \"")
                || context.contains("userInput")
                || context.contains("user_input")
                || context.contains("request.");

            if has_dynamic {
                findings.push(create_finding_with_confidence(
                    "go/command-injection",
                    node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Critical,
                    "Command injection: shell -c with dynamic input - validate/escape input",
                    Language::Go,
                    Confidence::High,
                ));
            } else {
                findings.push(create_finding_with_confidence(
                    "go/command-injection",
                    node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "Shell command with -c mode - ensure arguments are trusted",
                    Language::Go,
                    Confidence::Medium,
                ));
            }
        }
    }

    /// Check for SQL injection patterns
    fn check_sql_injection(&self, node: &Node, parsed: &ParsedFile, findings: &mut Vec<Finding>) {
        let text = match node.utf8_text(parsed.content.as_bytes()) {
            Ok(t) => t,
            Err(_) => return,
        };

        if contains_ignore_case(text, "select ")
            || contains_ignore_case(text, "insert ")
            || contains_ignore_case(text, "update ")
            || contains_ignore_case(text, "delete ")
        {
            findings.push(create_finding_with_confidence(
                "go/sql-injection",
                node,
                &parsed.path,
                &parsed.content,
                Severity::Critical,
                "SQL query built with fmt.Sprintf - use parameterized queries",
                Language::Go,
                Confidence::High,
            ));
        }
    }

    /// Check for unsafe type conversions
    fn check_type_conversion(&self, node: &Node, parsed: &ParsedFile, findings: &mut Vec<Finding>) {
        if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
            && text.contains("unsafe.Pointer")
        {
            findings.push(create_finding_with_confidence(
                "go/unsafe-pointer",
                node,
                &parsed.path,
                &parsed.content,
                Severity::Warning,
                "Conversion to unsafe.Pointer - requires careful review",
                Language::Go,
                Confidence::High,
            ));
        }
    }

    /// Check for ignored errors
    fn check_ignored_error(&self, node: &Node, parsed: &ParsedFile, findings: &mut Vec<Finding>) {
        if let Ok(text) = node.utf8_text(parsed.content.as_bytes())
            && text.contains(", _")
            && text.contains(":=")
            && !text.contains("err")
        {
            findings.push(create_finding_with_confidence(
                "go/ignored-error",
                node,
                &parsed.path,
                &parsed.content,
                Severity::Info,
                "Consider handling the error instead of discarding with _",
                Language::Go,
                Confidence::Low,
            ));
        }
    }
}

// =============================================================================
// INDIVIDUAL RULES (kept for backwards compatibility and granular control)
// =============================================================================

/// Detects command injection patterns
pub struct CommandInjectionRule;

impl Rule for CommandInjectionRule {
    fn id(&self) -> &str {
        "go/command-injection"
    }
    fn description(&self) -> &str {
        "Detects command injection patterns"
    }
    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        // Delegate to scanner for this specific check
        if !parsed.content.contains("os/exec") {
            return Vec::new();
        }
        let scanner = GoSecurityScanner;
        scanner
            .check(parsed)
            .into_iter()
            .filter(|f| f.rule_id == "go/command-injection")
            .collect()
    }
}

/// Detects SQL injection patterns
pub struct SqlInjectionRule;

impl Rule for SqlInjectionRule {
    fn id(&self) -> &str {
        "go/sql-injection"
    }
    fn description(&self) -> &str {
        "Detects SQL injection patterns"
    }
    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        if !parsed.content.contains("database/sql") && !parsed.content.contains("\"sql\"") {
            return Vec::new();
        }
        let scanner = GoSecurityScanner;
        scanner
            .check(parsed)
            .into_iter()
            .filter(|f| f.rule_id == "go/sql-injection")
            .collect()
    }
}

/// Detects unsafe pointer usage
pub struct UnsafePointerRule;

impl Rule for UnsafePointerRule {
    fn id(&self) -> &str {
        "go/unsafe-pointer"
    }
    fn description(&self) -> &str {
        "Detects unsafe.Pointer usage"
    }
    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        // Skip generated files - they use unsafe.Pointer intentionally
        if is_generated_file(&parsed.path, &parsed.content) {
            return Vec::new();
        }
        if !parsed.content.contains("\"unsafe\"") {
            return Vec::new();
        }
        let scanner = GoSecurityScanner;
        scanner
            .check(parsed)
            .into_iter()
            .filter(|f| f.rule_id == "go/unsafe-pointer")
            .collect()
    }
}

/// Detects insecure HTTP servers
pub struct InsecureHttpRule;

impl Rule for InsecureHttpRule {
    fn id(&self) -> &str {
        "go/insecure-http"
    }
    fn description(&self) -> &str {
        "Detects HTTP servers without TLS"
    }
    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        if !parsed.content.contains("net/http") {
            return Vec::new();
        }
        let scanner = GoSecurityScanner;
        scanner
            .check(parsed)
            .into_iter()
            .filter(|f| f.rule_id == "go/insecure-http")
            .collect()
    }
}

/// Detects ignored errors
pub struct IgnoredErrorHint;

impl Rule for IgnoredErrorHint {
    fn id(&self) -> &str {
        "go/ignored-error-hint"
    }
    fn description(&self) -> &str {
        "Detects ignored error values"
    }
    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let scanner = GoSecurityScanner;
        scanner
            .check(parsed)
            .into_iter()
            .filter(|f| f.rule_id == "go/ignored-error")
            .collect()
    }
}

// =============================================================================
// HELPER - Line-based finding creation
// =============================================================================

/// Create a finding from line/column numbers (for line-based scanning)
#[allow(clippy::too_many_arguments)]
fn create_line_based_finding(
    rule_id: &str,
    line: usize,
    column: usize,
    path: &std::path::Path,
    snippet: &str,
    severity: Severity,
    message: &str,
    language: Language,
    confidence: Confidence,
) -> Finding {
    let mut finding = Finding {
        id: format!("{}:{}:{}", rule_id, path.display(), line),
        rule_id: rule_id.to_string(),
        message: message.to_string(),
        severity,
        location: rma_common::SourceLocation::new(
            path.to_path_buf(),
            line,
            column,
            line,
            snippet.len().min(100),
        ),
        language,
        snippet: Some(snippet.trim().chars().take(200).collect()),
        suggestion: None,
        confidence,
        category: rma_common::FindingCategory::Security,
        fingerprint: None,
        properties: None,
    };
    finding.compute_fingerprint();
    finding
}

#[cfg(test)]
mod tests {
    use super::*;
    use rma_common::RmaConfig;
    use rma_parser::ParserEngine;
    use std::path::Path;

    #[test]
    fn test_unsafe_pointer_skipped_in_generated_files() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // Code with unsafe.Pointer usage (common in Kubernetes generated code)
        let content = r#"
// Code generated by controller-gen. DO NOT EDIT.

package v1

import (
    "unsafe"
)

func Convert(in, out interface{}) {
    out = (*string)(unsafe.Pointer(in.(*string)))
}
"#;

        // In a zz_generated file - should NOT produce findings
        let parsed_generated = parser
            .parse_file(
                Path::new("/project/pkg/apis/v1/zz_generated.conversion.go"),
                content,
            )
            .unwrap();
        let scanner = GoSecurityScanner;
        let findings_generated = scanner.check(&parsed_generated);

        let unsafe_findings: Vec<_> = findings_generated
            .iter()
            .filter(|f| f.rule_id == "go/unsafe-pointer")
            .collect();

        assert!(
            unsafe_findings.is_empty(),
            "Should skip unsafe.Pointer in generated files, but found: {:?}",
            unsafe_findings
        );

        // In a regular file - SHOULD produce findings
        let regular_content = r#"
package main

import (
    "unsafe"
)

func Convert(in, out interface{}) {
    out = (*string)(unsafe.Pointer(in.(*string)))
}
"#;
        let parsed_regular = parser
            .parse_file(Path::new("/project/pkg/convert.go"), regular_content)
            .unwrap();
        let findings_regular = scanner.check(&parsed_regular);

        let unsafe_findings_regular: Vec<_> = findings_regular
            .iter()
            .filter(|f| f.rule_id == "go/unsafe-pointer")
            .collect();

        assert!(
            !unsafe_findings_regular.is_empty(),
            "Should detect unsafe.Pointer in regular files"
        );
    }

    #[test]
    fn test_command_injection_detection() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import (
    "os/exec"
    "fmt"
)

func runCommand(userInput string) {
    cmd := fmt.Sprintf("echo %s", userInput)
    exec.Command("sh", "-c", cmd).Run()
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let injection_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/command-injection")
            .collect();

        assert!(
            !injection_findings.is_empty(),
            "Should detect injection pattern"
        );
    }

    #[test]
    fn test_hardcoded_credential() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

var password = "supersecret123"
var apiKey = "sk-1234567890abcdef"
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let cred_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/hardcoded-credential")
            .collect();

        assert!(
            !cred_findings.is_empty(),
            "Should detect hardcoded credentials"
        );
    }

    #[test]
    fn test_weak_crypto() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import "crypto/md5"

func hash(data []byte) []byte {
    h := md5.New()
    h.Write(data)
    return h.Sum(nil)
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let crypto_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.contains("crypto") || f.rule_id.contains("hash"))
            .collect();

        assert!(!crypto_findings.is_empty(), "Should detect weak crypto");
    }
}
