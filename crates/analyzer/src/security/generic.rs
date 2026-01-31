//! Generic security and code quality DETECTION rules
//!
//! These rules apply across multiple languages for static analysis.

use crate::rules::{create_finding, create_finding_at_line, Rule};
use regex::Regex;
use rma_common::{Finding, Language, Severity};
use rma_parser::ParsedFile;
use std::sync::LazyLock;
use tree_sitter::Node;

// Regex patterns for security checks
static SECRET_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(api[_-]?key|secret[_-]?key|password|passwd|token|auth[_-]?token|private[_-]?key|access[_-]?key|client[_-]?secret)\s*[:=]\s*["'][^"']{8,}["']"#).unwrap()
});

static AWS_KEY_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap()
});

static AWS_SECRET_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']"#).unwrap()
});

static GITHUB_TOKEN_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"gh[ps]_[A-Za-z0-9]{36,}"#).unwrap()
});

static PRIVATE_KEY_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"#).unwrap()
});

static GENERIC_SECRET_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(secret|password|passwd|pwd|token|key|credential|auth)\s*[:=]\s*["'][^"']{12,}["']"#).unwrap()
});

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
            if upper.contains("TODO")
                || upper.contains("FIXME")
                || upper.contains("HACK")
                || upper.contains("XXX")
            {
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
                    &format!(
                        "Function has {} lines (max: {}) - consider refactoring",
                        lines, self.max_lines
                    ),
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

/// DETECTS hardcoded secrets, API keys, and passwords in any language
pub struct HardcodedSecretRule;

impl Rule for HardcodedSecretRule {
    fn id(&self) -> &str {
        "generic/hardcoded-secret"
    }

    fn description(&self) -> &str {
        "Detects hardcoded secrets, API keys, and passwords"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in parsed.content.lines().enumerate() {
            let trimmed = line.trim();

            // Skip comments in various languages
            if trimmed.starts_with("//")
                || trimmed.starts_with('#')
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
                || trimmed.starts_with("'''")
                || trimmed.starts_with("\"\"\"")
            {
                continue;
            }

            // Check for API keys and secrets with assignment
            if SECRET_PATTERN.is_match(line) {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    "[REDACTED SECRET]",
                    Severity::Critical,
                    "Hardcoded secret detected - use environment variables or a secrets manager",
                    parsed.language,
                ));
                continue; // Don't report same line multiple times
            }

            // Check for AWS access keys
            if AWS_KEY_PATTERN.is_match(line) {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    "[REDACTED AWS KEY]",
                    Severity::Critical,
                    "AWS access key ID detected - never commit credentials",
                    parsed.language,
                ));
                continue;
            }

            // Check for AWS secret keys
            if AWS_SECRET_PATTERN.is_match(line) {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    "[REDACTED AWS SECRET]",
                    Severity::Critical,
                    "AWS secret access key detected - never commit credentials",
                    parsed.language,
                ));
                continue;
            }

            // Check for GitHub tokens
            if GITHUB_TOKEN_PATTERN.is_match(line) {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    "[REDACTED GITHUB TOKEN]",
                    Severity::Critical,
                    "GitHub token detected - use GITHUB_TOKEN secret instead",
                    parsed.language,
                ));
                continue;
            }

            // Check for private keys
            if PRIVATE_KEY_PATTERN.is_match(line) {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    "[REDACTED PRIVATE KEY]",
                    Severity::Critical,
                    "Private key detected in source - store in secure key management",
                    parsed.language,
                ));
                continue;
            }

            // Generic secret pattern (less specific, more false positives)
            if GENERIC_SECRET_PATTERN.is_match(line) && !line.contains("test") && !line.contains("example") {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    trimmed,
                    Severity::Warning,
                    "Potential hardcoded credential - verify this is not a real secret",
                    parsed.language,
                ));
            }
        }
        findings
    }
}

/// DETECTS use of weak cryptographic algorithms
pub struct InsecureCryptoRule;

impl Rule for InsecureCryptoRule {
    fn id(&self) -> &str {
        "generic/insecure-crypto"
    }

    fn description(&self) -> &str {
        "Detects use of weak or deprecated cryptographic algorithms"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in parsed.content.lines().enumerate() {
            let lower = line.to_lowercase();

            // Skip detection code (lines that are checking for patterns)
            if lower.contains(".contains(") || lower.contains(".is_match(") || lower.contains("regex") {
                continue;
            }

            // MD5 - broken for security use
            if lower.contains("md5") && (lower.contains("hash") || lower.contains("digest") || lower.contains("::") || lower.contains("import") || lower.contains("require")) {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    line.trim(),
                    Severity::Error,
                    "MD5 is cryptographically broken - use SHA-256 or better for security",
                    parsed.language,
                ));
            }

            // SHA-1 - deprecated for security
            if lower.contains("sha1") && !lower.contains("sha1sum") && (lower.contains("hash") || lower.contains("digest") || lower.contains("::") || lower.contains("import")) {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    line.trim(),
                    Severity::Warning,
                    "SHA-1 is deprecated for security - use SHA-256 or better",
                    parsed.language,
                ));
            }

            // DES - broken
            if (lower.contains("des") || lower.contains("3des") || lower.contains("triple_des"))
                && (lower.contains("encrypt") || lower.contains("cipher") || lower.contains("crypto"))
            {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    line.trim(),
                    Severity::Error,
                    "DES/3DES is insecure - use AES-256-GCM or ChaCha20-Poly1305",
                    parsed.language,
                ));
            }

            // RC4 - broken
            if lower.contains("rc4") && (lower.contains("cipher") || lower.contains("crypto") || lower.contains("encrypt")) {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    line.trim(),
                    Severity::Critical,
                    "RC4 is completely broken - use AES-GCM or ChaCha20-Poly1305",
                    parsed.language,
                ));
            }

            // ECB mode - insecure
            if lower.contains("ecb") && (lower.contains("mode") || lower.contains("cipher") || lower.contains("aes")) {
                findings.push(create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    line_num + 1,
                    line.trim(),
                    Severity::Error,
                    "ECB mode is insecure - use GCM, CBC with HMAC, or authenticated encryption",
                    parsed.language,
                ));
            }
        }
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
        Language::Rust => &[
            "if_expression",
            "match_expression",
            "while_expression",
            "for_expression",
        ],
        Language::JavaScript | Language::TypeScript => &[
            "if_statement",
            "switch_statement",
            "for_statement",
            "while_statement",
        ],
        Language::Python => &[
            "if_statement",
            "for_statement",
            "while_statement",
            "try_statement",
        ],
        Language::Go => &["if_statement", "for_statement", "switch_statement"],
        Language::Java => &[
            "if_statement",
            "for_statement",
            "while_statement",
            "switch_expression",
        ],
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
