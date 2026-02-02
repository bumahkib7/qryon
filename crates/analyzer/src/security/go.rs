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
//! - **Flow-Aware Rules**: Rules using CFG and taint analysis

use crate::flow::FlowContext;
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

/// Pattern to detect InsecureSkipVerify: true
static INSECURE_TLS_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"InsecureSkipVerify\s*:\s*true").unwrap());

/// Pattern to detect weak TLS versions (1.0 or 1.1)
static WEAK_TLS_VERSION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"MinVersion\s*:\s*tls\.(VersionTLS10|VersionTLS11|VersionSSL30)").unwrap()
});

/// Pattern to detect http.Client{} without Timeout
static HTTP_CLIENT_NO_TIMEOUT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"http\.Client\s*\{[^}]*\}").unwrap());

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
        let has_defer = parsed.content.contains("defer");
        let has_goroutine = parsed.content.contains("go ");
        let has_tls = parsed.content.contains("crypto/tls") || parsed.content.contains("tls.");

        // Skip unsafe pointer checks for generated files (e.g., Kubernetes zz_generated_*)
        // These files use unsafe.Pointer intentionally for performance-critical conversions
        let skip_unsafe_check = is_generated_file(&parsed.path, &parsed.content);

        // Line-based checks (credentials, weak crypto imports, TLS config, HTTP client)
        self.check_lines(parsed, &mut findings, has_crypto, has_tls, has_http);

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
            has_defer,
            has_goroutine,
        );

        findings
    }
}

impl GoSecurityScanner {
    /// Check lines for patterns (credentials, imports, TLS config, HTTP client)
    fn check_lines(
        &self,
        parsed: &ParsedFile,
        findings: &mut Vec<Finding>,
        has_crypto: bool,
        has_tls: bool,
        has_http: bool,
    ) {
        // Only skip credential checks in test/fixture files - they commonly contain fake secrets
        let is_test_file = is_test_or_fixture_file(&parsed.path);

        for (line_num, line) in parsed.content.lines().enumerate() {
            // Hardcoded credentials (skip in test files)
            if !is_test_file && CREDENTIAL_PATTERN.is_match(line) {
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

            // AWS keys (skip in test files)
            if !is_test_file && AWS_KEY_PATTERN.is_match(line) {
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

            // Insecure TLS config - InsecureSkipVerify: true
            if has_tls && INSECURE_TLS_PATTERN.is_match(line) {
                findings.push(create_line_based_finding(
                    "go/insecure-tls",
                    line_num + 1,
                    1,
                    &parsed.path,
                    line,
                    Severity::Error,
                    "InsecureSkipVerify disables TLS certificate verification - vulnerable to MITM attacks",
                    Language::Go,
                    Confidence::High,
                ));
            }

            // Insecure TLS config - weak MinVersion (TLS 1.0 or 1.1)
            if has_tls && WEAK_TLS_VERSION_PATTERN.is_match(line) {
                findings.push(create_line_based_finding(
                    "go/insecure-tls",
                    line_num + 1,
                    1,
                    &parsed.path,
                    line,
                    Severity::Error,
                    "Weak TLS version (1.0/1.1) - use tls.VersionTLS12 or tls.VersionTLS13",
                    Language::Go,
                    Confidence::High,
                ));
            }

            // HTTP client without timeout
            if has_http && HTTP_CLIENT_NO_TIMEOUT_PATTERN.is_match(line) {
                // Check if Timeout is set as a field in the struct literal
                // Look for "Timeout:" pattern (field assignment), not just "Timeout" anywhere
                // This avoids false negatives from comments mentioning Timeout
                let code_part = if let Some(idx) = line.find("//") {
                    &line[..idx]
                } else {
                    line
                };
                if !code_part.contains("Timeout:") && !code_part.contains("Timeout :") {
                    findings.push(create_line_based_finding(
                        "go/missing-http-timeout",
                        line_num + 1,
                        1,
                        &parsed.path,
                        line,
                        Severity::Warning,
                        "http.Client without Timeout - may hang indefinitely. Set Timeout field",
                        Language::Go,
                        Confidence::High,
                    ));
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
        has_defer: bool,
        has_goroutine: bool,
    ) {
        // Track loop depth for defer-in-loop detection
        let mut loop_depth: usize = 0;

        loop {
            let node = cursor.node();
            let kind = node.kind();

            // Track entering/exiting loops for defer-in-loop detection
            let is_loop = matches!(kind, "for_statement" | "range_clause");
            if is_loop {
                loop_depth += 1;
            }

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
                "defer_statement" if has_defer && loop_depth > 0 => {
                    self.check_defer_in_loop(&node, parsed, findings);
                }
                "go_statement" if has_goroutine => {
                    self.check_goroutine_leak(&node, parsed, findings);
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
                // Track exiting loops
                let parent_kind = cursor.node().kind();
                if matches!(parent_kind, "for_statement" | "range_clause") {
                    loop_depth = loop_depth.saturating_sub(1);
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

        // Missing HTTP timeout - http.Get/Post/Head/PostForm use default client with no timeout
        if has_http
            && (func_text == "http.Get"
                || func_text == "http.Post"
                || func_text == "http.Head"
                || func_text == "http.PostForm")
        {
            findings.push(create_finding_with_confidence(
                "go/missing-http-timeout",
                node,
                &parsed.path,
                &parsed.content,
                Severity::Warning,
                "http.Get/Post uses default client with no timeout - use custom http.Client with Timeout",
                Language::Go,
                Confidence::High,
            ));
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

    /// Check for defer statements inside loops
    /// Deferred calls accumulate until the function returns, not after each loop iteration
    fn check_defer_in_loop(&self, node: &Node, parsed: &ParsedFile, findings: &mut Vec<Finding>) {
        findings.push(create_finding_with_confidence(
            "go/defer-in-loop",
            node,
            &parsed.path,
            &parsed.content,
            Severity::Warning,
            "defer inside loop - deferred calls accumulate until function returns, causing resource buildup. Consider moving cleanup outside the loop or use an inner function",
            Language::Go,
            Confidence::High,
        ));
    }

    /// Check for goroutine leak patterns
    /// Detects: go func() without context, blocking channel operations without select
    fn check_goroutine_leak(&self, node: &Node, parsed: &ParsedFile, findings: &mut Vec<Finding>) {
        let text = match node.utf8_text(parsed.content.as_bytes()) {
            Ok(t) => t,
            Err(_) => return,
        };

        // Look at a broader context around the go statement
        let context_start = node.start_byte().saturating_sub(200);
        let context_end = (node.end_byte() + 500).min(parsed.content.len());
        let surrounding = &parsed.content[context_start..context_end];

        // Check if this is an inline goroutine (go func() or go func(...)
        // The go_statement node contains the full "go func() { ... }()" text
        let is_inline_goroutine = text.contains("func()") || text.contains("func(");

        if is_inline_goroutine {
            // Strip comments from text for more accurate detection
            let text_no_comments: String = text
                .lines()
                .map(|line| {
                    if let Some(idx) = line.find("//") {
                        &line[..idx]
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");

            // Check for context cancellation patterns (ignoring comments)
            let has_context_done = text_no_comments.contains("ctx.Done()")
                || text_no_comments.contains("<-ctx.Done()");
            let has_select =
                text_no_comments.contains("select {") || text_no_comments.contains("select{");
            let has_context_param = text_no_comments.contains("ctx context.Context")
                || text_no_comments.contains("ctx Context")
                || surrounding.contains("context.WithCancel")
                || surrounding.contains("context.WithTimeout")
                || surrounding.contains("context.WithDeadline");

            // Detect blocking channel operations (channel receive without ctx.Done)
            let has_channel_receive =
                text_no_comments.contains("<-") && !text_no_comments.contains("<-ctx.Done()");

            // If no context cancellation mechanism and has potential blocking ops
            if !has_context_done && !has_select && has_channel_receive {
                findings.push(create_finding_with_confidence(
                    "go/goroutine-leak",
                    node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "Goroutine with channel receive without select/ctx.Done() - may block forever causing leak",
                    Language::Go,
                    Confidence::Medium,
                ));
                return;
            }

            // If no context used at all and it's a long-running goroutine pattern
            if !has_context_param
                && !has_context_done
                && (text_no_comments.contains("for {")
                    || text_no_comments.contains("for{")
                    || text_no_comments.contains("for true"))
            {
                findings.push(create_finding_with_confidence(
                    "go/goroutine-leak",
                    node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "Goroutine with infinite loop without context cancellation - use context.Context for graceful shutdown",
                    Language::Go,
                    Confidence::Medium,
                ));
                return;
            }

            // Check for missing select with Done channel in blocking operations
            if has_channel_receive && !has_select && has_context_param && !has_context_done {
                findings.push(create_finding_with_confidence(
                    "go/goroutine-leak",
                    node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Warning,
                    "Goroutine with context but missing select with ctx.Done() - may not respond to cancellation",
                    Language::Go,
                    Confidence::Medium,
                ));
            }
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

/// Detects defer statements inside loops
pub struct DeferInLoopRule;

impl Rule for DeferInLoopRule {
    fn id(&self) -> &str {
        "go/defer-in-loop"
    }
    fn description(&self) -> &str {
        "Detects defer statements inside for loops causing resource accumulation"
    }
    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        if !parsed.content.contains("defer") {
            return Vec::new();
        }
        let scanner = GoSecurityScanner;
        scanner
            .check(parsed)
            .into_iter()
            .filter(|f| f.rule_id == "go/defer-in-loop")
            .collect()
    }
}

/// Detects goroutine leak patterns
pub struct GoroutineLeakRule;

impl Rule for GoroutineLeakRule {
    fn id(&self) -> &str {
        "go/goroutine-leak"
    }
    fn description(&self) -> &str {
        "Detects goroutines that may leak due to missing context cancellation or blocking channels"
    }
    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        if !parsed.content.contains("go ") {
            return Vec::new();
        }
        let scanner = GoSecurityScanner;
        scanner
            .check(parsed)
            .into_iter()
            .filter(|f| f.rule_id == "go/goroutine-leak")
            .collect()
    }
}

/// Detects HTTP clients without timeout configuration
pub struct MissingHttpTimeoutRule;

impl Rule for MissingHttpTimeoutRule {
    fn id(&self) -> &str {
        "go/missing-http-timeout"
    }
    fn description(&self) -> &str {
        "Detects http.Client without Timeout or use of http.Get/Post (default client has no timeout)"
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
            .filter(|f| f.rule_id == "go/missing-http-timeout")
            .collect()
    }
}

/// Detects insecure TLS configurations
pub struct InsecureTlsRule;

impl Rule for InsecureTlsRule {
    fn id(&self) -> &str {
        "go/insecure-tls"
    }
    fn description(&self) -> &str {
        "Detects InsecureSkipVerify: true or weak TLS versions (1.0/1.1)"
    }
    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        if !parsed.content.contains("crypto/tls") && !parsed.content.contains("tls.") {
            return Vec::new();
        }
        let scanner = GoSecurityScanner;
        scanner
            .check(parsed)
            .into_iter()
            .filter(|f| f.rule_id == "go/insecure-tls")
            .collect()
    }
}

// =============================================================================
// FLOW-AWARE RULES
// =============================================================================

/// Detects errors that are checked on some paths but not all (using CFG analysis)
///
/// In Go, errors should always be checked before using the associated value.
/// This rule uses CFG analysis to detect cases where error checking can be bypassed.
///
/// Pattern detected:
/// ```go
/// result, err := someOperation()
/// if condition {
///     if err != nil { return err }
/// }
/// // err might not be checked here!
/// useResult(result)
/// ```
///
/// Confidence: MEDIUM (requires understanding of control flow)
pub struct UncheckedErrorRule;

impl Rule for UncheckedErrorRule {
    fn id(&self) -> &str {
        "go/unchecked-error"
    }

    fn description(&self) -> &str {
        "Detects errors that may not be checked on all code paths"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Go
    }

    fn uses_flow(&self) -> bool {
        true
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        // Requires flow context - see check_with_flow
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Find all short variable declarations that might return errors
        find_short_var_decls(&mut cursor, |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Look for patterns like: result, err := ...
                if text.contains(", err :=") || text.contains(",err:=") {
                    // Get the block containing this declaration
                    let decl_block = flow.cfg.block_of(node.id());

                    // Look ahead to find if there's an error check
                    if let Some(parent) = find_function_body(node) {
                        let has_error_check = check_for_error_handling(
                            parent,
                            node.end_byte(),
                            parsed.content.as_bytes(),
                        );

                        // If no immediate error check, warn
                        if !has_error_check {
                            // Check if we're inside a conditional block (partial check)
                            let in_conditional = decl_block
                                .map(|b| {
                                    flow.cfg.predecessors(b).len() > 1
                                        || matches!(
                                            flow.cfg.blocks.get(b).map(|bb| &bb.terminator),
                                            Some(crate::flow::Terminator::Branch { .. })
                                        )
                                })
                                .unwrap_or(false);

                            if in_conditional {
                                findings.push(create_finding_with_confidence(
                                    self.id(),
                                    &node,
                                    &parsed.path,
                                    &parsed.content,
                                    Severity::Warning,
                                    "Error may not be checked on all code paths",
                                    Language::Go,
                                    Confidence::Medium,
                                ));
                            }
                        }
                    }
                }
            }
        });

        findings
    }
}

/// Find function body containing a node
fn find_function_body(node: Node) -> Option<Node> {
    let mut current = node.parent();
    while let Some(n) = current {
        if n.kind() == "function_declaration" || n.kind() == "method_declaration" {
            return n.child_by_field_name("body");
        }
        current = n.parent();
    }
    None
}

/// Check if there's an error check after the given position
fn check_for_error_handling(body: Node, after_pos: usize, source: &[u8]) -> bool {
    // Simple heuristic: look for "if err != nil" or "if err == nil" after the position
    let body_text = body.utf8_text(source).unwrap_or("");
    let remaining = if after_pos < body.start_byte() {
        body_text
    } else {
        let offset = after_pos.saturating_sub(body.start_byte());
        if offset < body_text.len() {
            &body_text[offset..]
        } else {
            ""
        }
    };

    // Look for error checks within the next 200 characters
    let check_range = remaining.chars().take(200).collect::<String>();
    check_range.contains("err != nil")
        || check_range.contains("err == nil")
        || check_range.contains("if err")
}

/// Helper to find short variable declarations
fn find_short_var_decls<F>(cursor: &mut tree_sitter::TreeCursor, mut callback: F)
where
    F: FnMut(Node),
{
    loop {
        let node = cursor.node();
        if node.kind() == "short_var_declaration" {
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
        fix: None,
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

    #[test]
    fn test_defer_in_loop() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import "os"

func processFiles(files []string) {
    for _, file := range files {
        f, _ := os.Open(file)
        defer f.Close() // BAD: deferred calls accumulate
    }
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let defer_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/defer-in-loop")
            .collect();

        assert!(
            !defer_findings.is_empty(),
            "Should detect defer inside loop"
        );
    }

    #[test]
    fn test_defer_outside_loop_no_finding() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import "os"

func processFile(file string) {
    f, _ := os.Open(file)
    defer f.Close() // OK: defer outside loop
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let defer_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/defer-in-loop")
            .collect();

        assert!(
            defer_findings.is_empty(),
            "Should not report defer outside loop"
        );
    }

    #[test]
    fn test_goroutine_leak_blocking_channel() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

func leakyGoroutine(ch chan int) {
    go func() {
        val := <-ch // BAD: may block forever without select/ctx.Done()
        println(val)
    }()
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let leak_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/goroutine-leak")
            .collect();

        assert!(
            !leak_findings.is_empty(),
            "Should detect goroutine with blocking channel"
        );
    }

    #[test]
    fn test_goroutine_leak_infinite_loop_no_context() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

func leakyWorker() {
    go func() {
        for {
            // BAD: infinite loop without context cancellation
            doWork()
        }
    }()
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let leak_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/goroutine-leak")
            .collect();

        assert!(
            !leak_findings.is_empty(),
            "Should detect goroutine with infinite loop and no context"
        );
    }

    #[test]
    fn test_goroutine_with_context_done_no_finding() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import "context"

func safeWorker(ctx context.Context) {
    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            default:
                doWork()
            }
        }
    }()
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let leak_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/goroutine-leak")
            .collect();

        assert!(
            leak_findings.is_empty(),
            "Should not report goroutine with proper context handling"
        );
    }

    #[test]
    fn test_missing_http_timeout_default_client() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import "net/http"

func fetchData(url string) {
    resp, _ := http.Get(url) // BAD: uses default client with no timeout
    defer resp.Body.Close()
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let timeout_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/missing-http-timeout")
            .collect();

        assert!(
            !timeout_findings.is_empty(),
            "Should detect http.Get without timeout"
        );
    }

    #[test]
    fn test_missing_http_timeout_client_no_timeout() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import "net/http"

func fetchData(url string) {
    client := &http.Client{} // BAD: no Timeout field
    resp, _ := client.Get(url)
    defer resp.Body.Close()
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let timeout_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/missing-http-timeout")
            .collect();

        assert!(
            !timeout_findings.is_empty(),
            "Should detect http.Client without Timeout"
        );
    }

    #[test]
    fn test_http_client_with_timeout_no_finding() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import (
    "net/http"
    "time"
)

func fetchData(url string) {
    client := &http.Client{Timeout: 30 * time.Second}
    resp, _ := client.Get(url)
    defer resp.Body.Close()
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let timeout_findings: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.rule_id == "go/missing-http-timeout"
                    && f.message.contains("http.Client without Timeout")
            })
            .collect();

        assert!(
            timeout_findings.is_empty(),
            "Should not report http.Client with Timeout"
        );
    }

    #[test]
    fn test_insecure_tls_skip_verify() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import "crypto/tls"

func insecureClient() *tls.Config {
    return &tls.Config{
        InsecureSkipVerify: true, // BAD: disables certificate verification
    }
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let tls_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/insecure-tls")
            .collect();

        assert!(
            !tls_findings.is_empty(),
            "Should detect InsecureSkipVerify: true"
        );
        assert_eq!(
            tls_findings[0].severity,
            Severity::Error,
            "InsecureSkipVerify should be Error severity"
        );
    }

    #[test]
    fn test_insecure_tls_weak_version() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import "crypto/tls"

func weakTLS() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS10, // BAD: TLS 1.0 is deprecated
    }
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let tls_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/insecure-tls")
            .collect();

        assert!(!tls_findings.is_empty(), "Should detect weak TLS version");
    }

    #[test]
    fn test_secure_tls_no_finding() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
package main

import "crypto/tls"

func secureTLS() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS13,
        InsecureSkipVerify: false,
    }
}
"#;

        let parsed = parser.parse_file(Path::new("main.go"), content).unwrap();
        let scanner = GoSecurityScanner;
        let findings = scanner.check(&parsed);

        let tls_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go/insecure-tls")
            .collect();

        assert!(
            tls_findings.is_empty(),
            "Should not report secure TLS config"
        );
    }
}
