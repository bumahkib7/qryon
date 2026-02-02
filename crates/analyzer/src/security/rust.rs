//! Rust-specific security rules
//!
//! Categorized into:
//! - **Sinks (High Confidence)**: Precise detection of dangerous patterns
//! - **Review Hints (Low Confidence)**: Patterns that need human review
//! - **Flow-Sensitive Rules**: Rules using CFG/dataflow analysis

use crate::flow::FlowContext;
use crate::rules::{Rule, create_finding_with_confidence};
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

/// Detects actual command injection patterns - shell mode with dynamic arguments
///
/// Only flags as CRITICAL when BOTH conditions are met:
/// 1. Shell invocation with -c, /C, or -Command mode
/// 2. Dynamic argument composition (format!, variables, concat)
///
/// Plain `Command::new("cmd")` without shell mode is NOT injection.
/// Confidence: HIGH (requires evidence of injection pattern)
pub struct CommandInjectionRule;

impl CommandInjectionRule {
    /// Check if a method chain on Command has shell mode AND dynamic args
    fn has_injection_pattern(content: &str, start_byte: usize, end_byte: usize) -> bool {
        // Get surrounding context (the full statement)
        let search_end = (end_byte + 500).min(content.len());
        let context = &content[start_byte..search_end];

        // Must have shell execution mode
        let has_shell_mode = context.contains("\"-c\"")
            || context.contains("\"/C\"")
            || context.contains("\"-Command\"")
            || context.contains("[\"-c\",")
            || context.contains("[\"/C\",");

        // Must have dynamic argument composition
        let has_dynamic_args = context.contains("format!(")
            || context.contains("&format!(")
            || context.contains(".arg(user")
            || context.contains(".arg(input")
            || context.contains(".arg(cmd")
            || context.contains(".arg(query")
            || context.contains(".args(&")
            || context.contains(".args(vec![");

        has_shell_mode && has_dynamic_args
    }
}

impl Rule for CommandInjectionRule {
    fn id(&self) -> &str {
        "rust/command-injection"
    }

    fn description(&self) -> &str {
        "Detects command injection patterns (shell mode with dynamic arguments)"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child(0)
                && let Some(args) = node.child_by_field_name("arguments")
            {
                let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                // Look for Command::new with shell program
                if func_text.ends_with("Command::new") || func_text == "Command::new" {
                    let args_text = args.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                    // Check if calling a shell
                    let is_shell = args_text.contains("\"sh\"")
                        || args_text.contains("\"bash\"")
                        || args_text.contains("\"/bin/sh\"")
                        || args_text.contains("\"/bin/bash\"")
                        || args_text.contains("\"cmd\"")
                        || args_text.contains("\"powershell\"")
                        || args_text.contains("\"cmd.exe\"")
                        || args_text.contains("\"powershell.exe\"");

                    if is_shell
                        && Self::has_injection_pattern(
                            &parsed.content,
                            node.start_byte(),
                            node.end_byte(),
                        )
                    {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Critical,
                            "Command injection: shell mode with dynamic arguments - validate and sanitize input",
                            Language::Rust,
                            Confidence::High,
                        ));
                    }
                    // No else - plain shell spawn without dynamic args is NOT injection
                }
            }
        });
        findings
    }
}

/// Detects shell process spawning (informational - for security policy)
///
/// This is NOT command injection - just awareness that a shell is being spawned.
/// Severity: INFO (policy awareness, not a vulnerability)
pub struct ShellSpawnRule;

impl Rule for ShellSpawnRule {
    fn id(&self) -> &str {
        "rust/shell-spawn"
    }

    fn description(&self) -> &str {
        "Detects shell process spawning (for security policy awareness)"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child(0)
                && let Some(args) = node.child_by_field_name("arguments")
            {
                let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                if func_text.ends_with("Command::new") || func_text == "Command::new" {
                    let args_text = args.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                    let is_shell = args_text.contains("\"sh\"")
                        || args_text.contains("\"bash\"")
                        || args_text.contains("\"/bin/sh\"")
                        || args_text.contains("\"/bin/bash\"")
                        || args_text.contains("\"cmd\"")
                        || args_text.contains("\"powershell\"");

                    if is_shell {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Info,
                            "Shell process spawn - ensure arguments are controlled and expected",
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
                let macro_text = macro_node
                    .utf8_text(parsed.content.as_bytes())
                    .unwrap_or("");

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
// SECTION C: FLOW-SENSITIVE RULES
// These rules use CFG and dataflow analysis for more precise detection
// =============================================================================

/// Detects `.unwrap()` on Results from I/O operations that may fail due to user input
///
/// This rule uses CFG analysis to detect .unwrap() calls on Results from:
/// - std::fs::* operations (file system)
/// - std::io::* operations (I/O)
/// - Network operations (TcpStream, etc.)
///
/// It checks if the error is properly handled before the unwrap call.
/// Confidence: MEDIUM (requires context to determine if input is actually user-controlled)
pub struct UnwrapOnUserInputRule;

impl UnwrapOnUserInputRule {
    /// I/O operations that return Result and may fail due to user input
    const IO_OPERATIONS: &'static [&'static str] = &[
        // File system operations
        "File::open",
        "File::create",
        "fs::read",
        "fs::read_to_string",
        "fs::write",
        "fs::read_dir",
        "fs::metadata",
        "fs::remove_file",
        "fs::remove_dir",
        "fs::create_dir",
        "fs::copy",
        "fs::rename",
        "std::fs::read",
        "std::fs::write",
        "std::fs::read_to_string",
        "std::fs::read_dir",
        "std::fs::metadata",
        "OpenOptions::open",
        // I/O operations
        "BufReader::new",
        "BufWriter::new",
        "Read::read",
        "Write::write",
        "Write::write_all",
        "io::stdin",
        "io::copy",
        "std::io::stdin",
        // Network operations
        "TcpStream::connect",
        "TcpListener::bind",
        "UdpSocket::bind",
        "UdpSocket::connect",
        "ToSocketAddrs::to_socket_addrs",
        "std::net::TcpStream::connect",
        "std::net::TcpListener::bind",
    ];

    /// Check if there's error handling (? operator, match, if let) before the unwrap
    fn has_error_handling_before(content: &str, unwrap_start: usize, io_op_start: usize) -> bool {
        let region = &content[io_op_start..unwrap_start];

        // Check for ? operator usage
        if region.contains('?') {
            return true;
        }

        // Check for match expression on the result
        if region.contains("match ")
            || region.contains("if let Ok(")
            || region.contains("if let Err(")
        {
            return true;
        }

        // Check for .is_ok() or .is_err() checks
        if region.contains(".is_ok()") || region.contains(".is_err()") {
            return true;
        }

        // Check for .ok() which converts Result to Option (acceptable pattern)
        if region.contains(".ok()") {
            return true;
        }

        false
    }

    /// Extract the receiver of a method chain to find the source operation
    fn find_io_source_in_chain<'a>(node: &Node<'a>, content: &'a str) -> Option<(String, usize)> {
        let full_text = node.utf8_text(content.as_bytes()).ok()?;

        // Walk up the method chain to find the source
        for op in Self::IO_OPERATIONS {
            if full_text.contains(op) {
                return Some((op.to_string(), node.start_byte()));
            }
        }

        // Check parent nodes for the source
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if let Ok(parent_text) = parent.utf8_text(content.as_bytes()) {
                for op in Self::IO_OPERATIONS {
                    if parent_text.contains(op) && !parent_text.contains(".unwrap()") {
                        // Found the I/O operation before unwrap
                        return Some((op.to_string(), parent.start_byte()));
                    }
                }
            }
            current = parent;
        }

        None
    }
}

impl Rule for UnwrapOnUserInputRule {
    fn id(&self) -> &str {
        "rust/unwrap-on-user-input"
    }

    fn description(&self) -> &str {
        "Detects .unwrap() on Results from I/O operations that may fail due to user input"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        // This rule uses flow analysis
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child(0) {
                // Check if this is an .unwrap() call
                if func.kind() == "field_expression" {
                    let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                    if func_text.ends_with(".unwrap") {
                        // Find if this unwrap is on a Result from an I/O operation
                        if let Some((io_op, io_start)) =
                            Self::find_io_source_in_chain(&func, &parsed.content)
                        {
                            // Check if error is properly handled before unwrap
                            if !Self::has_error_handling_before(
                                &parsed.content,
                                node.start_byte(),
                                io_start,
                            ) {
                                // Use CFG to check if we're in a context where error
                                // handling might have happened on a different path
                                let block_id = flow.cfg.block_of(node.id());

                                // Check if this is reachable and not in a catch block
                                let is_problematic = block_id
                                    .map(|bid| {
                                        flow.cfg.is_reachable(bid) && !flow.cfg.is_catch_block(bid)
                                    })
                                    .unwrap_or(true);

                                if is_problematic {
                                    findings.push(create_finding_with_confidence(
                                        self.id(),
                                        &node,
                                        &parsed.path,
                                        &parsed.content,
                                        Severity::Warning,
                                        &format!(
                                            "Calling .unwrap() on Result from {} - may panic on I/O error. \
                                             Consider using ? operator or proper error handling.",
                                            io_op
                                        ),
                                        Language::Rust,
                                        Confidence::Medium,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        });
        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

/// Detects functions returning `Result` that use `.unwrap()` instead of `?` operator
///
/// When a function returns Result, using .unwrap() inside it is usually a mistake -
/// the error should be propagated with ? instead.
///
/// Confidence: LOW (may have legitimate uses like in closures or when error types don't match)
pub struct MissingErrorPropagationRule;

impl MissingErrorPropagationRule {
    /// Check if a node is inside a closure
    fn is_in_closure(node: &Node) -> bool {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "closure_expression" {
                return true;
            }
            // Stop at function boundary
            if parent.kind() == "function_item" {
                return false;
            }
            current = parent;
        }
        false
    }

    /// Find the enclosing function and check if it returns Result
    fn enclosing_function_returns_result<'a>(
        node: &Node<'a>,
        content: &'a str,
    ) -> Option<(String, bool)> {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_item" {
                // Check return type
                if let Some(return_type) = parent.child_by_field_name("return_type") {
                    let type_text = return_type.utf8_text(content.as_bytes()).ok()?;
                    // Check if return type is Result
                    let returns_result = type_text.contains("Result<")
                        || type_text.contains("Result ")
                        || type_text == "Result";

                    // Get function name
                    let func_name = parent
                        .child_by_field_name("name")
                        .and_then(|n| n.utf8_text(content.as_bytes()).ok())
                        .unwrap_or("unknown")
                        .to_string();

                    return Some((func_name, returns_result));
                }
                return None;
            }
            current = parent;
        }
        None
    }
}

impl Rule for MissingErrorPropagationRule {
    fn id(&self) -> &str {
        "rust/missing-error-propagation"
    }

    fn description(&self) -> &str {
        "Detects functions returning Result that use .unwrap() instead of ? operator"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child(0) {
                if func.kind() == "field_expression" {
                    let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                    // Check for .unwrap() or .expect() calls
                    if func_text.ends_with(".unwrap") || func_text.ends_with(".expect") {
                        // Skip if inside a closure (closures often can't use ?)
                        if Self::is_in_closure(&node) {
                            return;
                        }

                        // Check if the enclosing function returns Result
                        if let Some((func_name, returns_result)) =
                            Self::enclosing_function_returns_result(&node, &parsed.content)
                        {
                            if returns_result {
                                let method = if func_text.ends_with(".unwrap") {
                                    "unwrap()"
                                } else {
                                    "expect()"
                                };
                                findings.push(create_finding_with_confidence(
                                    self.id(),
                                    &node,
                                    &parsed.path,
                                    &parsed.content,
                                    Severity::Info,
                                    &format!(
                                        "Function '{}' returns Result but uses .{} - \
                                         consider using ? operator to propagate errors instead",
                                        func_name, method
                                    ),
                                    Language::Rust,
                                    Confidence::Low,
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

/// Detects raw SQL queries that may be vulnerable to SQL injection
///
/// This rule improves on the basic SQL injection hint by detecting:
/// - sqlx::query!() with format strings
/// - diesel::sql_query() with string concatenation
/// - sea_orm raw queries
/// - rusqlite execute with format!
///
/// Confidence: MEDIUM (detects actual patterns but context matters)
pub struct RawSqlQueryRule;

impl RawSqlQueryRule {
    /// SQL-related function patterns to check
    const SQL_FUNCTIONS: &'static [&'static str] = &[
        // sqlx
        "sqlx::query",
        "query!",
        "query_as!",
        "query_scalar!",
        "query_as_with",
        "query_with",
        // diesel
        "diesel::sql_query",
        "sql_query",
        "diesel::dsl::sql",
        // sea_orm
        "Statement::from_sql_and_values",
        "Statement::from_string",
        "DbBackend::build",
        "sea_orm::Statement",
        // rusqlite
        "conn.execute",
        "conn.query_row",
        "conn.prepare",
        "Connection::execute",
        "Connection::query_row",
        "Statement::execute",
        // postgres
        "client.query",
        "client.execute",
        "Client::query",
        "Client::execute",
        // tokio-postgres
        "client.query_one",
        "client.query_opt",
    ];

    /// Check if text contains dynamic string building patterns
    fn has_dynamic_string_pattern(text: &str) -> bool {
        // format! macro
        if text.contains("format!(") {
            return true;
        }

        // String concatenation with +
        if text.contains("+ &") || text.contains("+ \"") || text.contains("\" +") {
            return true;
        }

        // format_args! macro
        if text.contains("format_args!(") {
            return true;
        }

        // concat! macro with non-literals (less common but possible)
        if text.contains("concat!(") && (text.contains("&") || text.contains("$")) {
            return true;
        }

        // String interpolation patterns in raw strings
        if text.contains(".to_string()") && (text.contains("+") || text.contains("push_str")) {
            return true;
        }

        false
    }

    /// Check if the SQL call uses parameterized queries properly
    fn uses_parameterized_query(text: &str) -> bool {
        // Check for bind/parameter markers
        text.contains(".bind(")
            || text.contains("$1")
            || text.contains("$2")
            || text.contains(":1")
            || text.contains(":2")
            || text.contains("?1")
            || text.contains("?2")
            // Named parameters
            || text.contains(":name")
            || text.contains("@")
            // sqlx macro with bound parameters
            || (text.contains("query!(") && text.contains(","))
    }
}

impl Rule for RawSqlQueryRule {
    fn id(&self) -> &str {
        "rust/raw-sql-query"
    }

    fn description(&self) -> &str {
        "Detects raw SQL queries with dynamic string building that may be vulnerable to SQL injection"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Quick check: only analyze files that likely use SQL
        let has_sql_context = parsed.content.contains("sqlx")
            || parsed.content.contains("diesel")
            || parsed.content.contains("sea_orm")
            || parsed.content.contains("rusqlite")
            || parsed.content.contains("postgres")
            || parsed.content.contains("mysql");

        if !has_sql_context {
            return findings;
        }

        let mut cursor = parsed.tree.walk();

        // Check macro invocations
        find_nodes_by_kind(&mut cursor, "macro_invocation", |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Check for query macros with format strings
                let is_sql_macro = text.starts_with("query!")
                    || text.starts_with("query_as!")
                    || text.starts_with("query_scalar!")
                    || text.starts_with("sql_query!");

                if is_sql_macro && Self::has_dynamic_string_pattern(text) {
                    // Check if it's not using proper parameterization
                    if !Self::uses_parameterized_query(text) {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "SQL macro with dynamic string building - use parameterized queries ($1, $2, ...) instead of string interpolation",
                            Language::Rust,
                            Confidence::Medium,
                        ));
                    }
                }

                // Check for format! containing SQL keywords
                if text.starts_with("format!(") {
                    let lower = text.to_lowercase();
                    let has_sql_keywords = lower.contains("select ")
                        || lower.contains("insert ")
                        || lower.contains("update ")
                        || lower.contains("delete ")
                        || lower.contains(" from ")
                        || lower.contains(" where ");

                    if has_sql_keywords {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "format!() with SQL keywords - potential SQL injection. Use parameterized queries instead",
                            Language::Rust,
                            Confidence::Medium,
                        ));
                    }
                }
            }
        });

        // Check function calls
        let mut cursor2 = parsed.tree.walk();
        find_nodes_by_kind(&mut cursor2, "call_expression", |node: Node| {
            if let Some(func) = node.child(0) {
                let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                // Check if it's a SQL-related function
                let is_sql_func = Self::SQL_FUNCTIONS
                    .iter()
                    .any(|f| func_text.ends_with(f) || func_text.contains(&format!("::{}", f)));

                if is_sql_func {
                    // Get the full call including arguments
                    if let Ok(full_text) = node.utf8_text(parsed.content.as_bytes()) {
                        if Self::has_dynamic_string_pattern(full_text)
                            && !Self::uses_parameterized_query(full_text)
                        {
                            findings.push(create_finding_with_confidence(
                                self.id(),
                                &node,
                                &parsed.path,
                                &parsed.content,
                                Severity::Warning,
                                &format!(
                                    "SQL function '{}' with dynamic string building - \
                                     use parameterized queries to prevent SQL injection",
                                    func_text
                                ),
                                Language::Rust,
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

// =============================================================================
// SECTION D: CONTEXT-AWARE RULES
// These rules use framework/context detection for more accurate severity
// =============================================================================

/// Detects `.unwrap()` and `.expect()` calls inside web framework handlers
///
/// Panics in handler code are especially dangerous because they crash the entire
/// server thread/process, affecting all users. This rule detects unwrap/expect
/// in handlers for:
/// - Actix-web: `#[get(...)]`, `#[post(...)]`, `#[put(...)]`, `#[delete(...)]`, `#[route(...)]`
/// - Axum: functions returning `impl IntoResponse` or `Response`
/// - Rocket: `#[get(...)]`, `#[post(...)]`, etc.
///
/// Excludes:
/// - Test functions (`#[test]`, `test_*`, `#[cfg(test)]`)
/// - `main()` function
/// - Functions using `?` operator (proper error handling)
///
/// Confidence: MEDIUM (requires heuristic detection of handler context)
pub struct UnwrapInHandlerRule;

impl UnwrapInHandlerRule {
    /// HTTP route attribute patterns that indicate a handler function
    const HANDLER_ATTRIBUTES: &'static [&'static str] = &[
        // Actix-web / Rocket route macros
        "#[get",
        "#[post",
        "#[put",
        "#[delete",
        "#[patch",
        "#[head",
        "#[options",
        "#[route",
        // Axum debug handler
        "#[axum::debug_handler",
        "#[debug_handler",
        // Generic handler marker
        "#[handler",
    ];

    /// Return type patterns that indicate a handler function
    const HANDLER_RETURN_TYPES: &'static [&'static str] = &[
        "HttpResponse",
        "impl Responder",
        "impl IntoResponse",
        "Response",
        "Result<HttpResponse",
        "Result<impl Responder",
        "Result<impl IntoResponse",
        "Result<Response",
        "Json<",
        "Html<",
        "Redirect",
    ];

    /// Check if a function has handler attributes
    fn has_handler_attribute(func_node: &Node, content: &str) -> bool {
        // Look for attribute_item nodes before the function
        let mut current = *func_node;
        while let Some(prev_sibling) = current.prev_sibling() {
            if prev_sibling.kind() == "attribute_item" {
                if let Ok(attr_text) = prev_sibling.utf8_text(content.as_bytes()) {
                    for pattern in Self::HANDLER_ATTRIBUTES {
                        if attr_text.starts_with(pattern) {
                            return true;
                        }
                    }
                }
            } else if prev_sibling.kind() != "attribute_item"
                && prev_sibling.kind() != "line_comment"
                && prev_sibling.kind() != "block_comment"
            {
                // Stop if we hit something that's not an attribute or comment
                break;
            }
            current = prev_sibling;
        }

        false
    }

    /// Check if a function has a handler-like return type
    fn has_handler_return_type(func_node: &Node, content: &str) -> bool {
        if let Some(return_type) = func_node.child_by_field_name("return_type") {
            if let Ok(type_text) = return_type.utf8_text(content.as_bytes()) {
                for pattern in Self::HANDLER_RETURN_TYPES {
                    if type_text.contains(pattern) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if a function is in a test context
    fn is_test_context(func_node: &Node, content: &str) -> bool {
        // Check for #[test] attribute
        let mut current = *func_node;
        while let Some(prev_sibling) = current.prev_sibling() {
            if prev_sibling.kind() == "attribute_item" {
                if let Ok(attr_text) = prev_sibling.utf8_text(content.as_bytes()) {
                    if attr_text.contains("#[test]")
                        || attr_text.contains("#[tokio::test]")
                        || attr_text.contains("#[async_std::test]")
                    {
                        return true;
                    }
                }
            } else if prev_sibling.kind() != "attribute_item"
                && prev_sibling.kind() != "line_comment"
                && prev_sibling.kind() != "block_comment"
            {
                break;
            }
            current = prev_sibling;
        }

        // Check for test_ prefix in function name
        if let Some(name_node) = func_node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                if name.starts_with("test_") {
                    return true;
                }
            }
        }

        // Check if we're inside a #[cfg(test)] module
        let mut parent = func_node.parent();
        while let Some(p) = parent {
            if p.kind() == "mod_item" {
                // Look for #[cfg(test)] attribute on the module
                let mut mod_current = p;
                while let Some(prev) = mod_current.prev_sibling() {
                    if prev.kind() == "attribute_item" {
                        if let Ok(attr_text) = prev.utf8_text(content.as_bytes()) {
                            if attr_text.contains("#[cfg(test)]") {
                                return true;
                            }
                        }
                    } else if prev.kind() != "attribute_item"
                        && prev.kind() != "line_comment"
                        && prev.kind() != "block_comment"
                    {
                        break;
                    }
                    mod_current = prev;
                }
            }
            parent = p.parent();
        }

        false
    }

    /// Check if a function is the main function
    fn is_main_function(func_node: &Node, content: &str) -> bool {
        if let Some(name_node) = func_node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(content.as_bytes()) {
                return name == "main";
            }
        }
        false
    }

    /// Check if a node is inside a closure (closures often can't use ?)
    fn is_in_closure(node: &Node) -> bool {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "closure_expression" {
                return true;
            }
            // Stop at function boundary
            if parent.kind() == "function_item" {
                return false;
            }
            current = parent;
        }
        false
    }

    /// Find the enclosing function for a node
    fn find_enclosing_function<'a>(node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_item" {
                return Some(parent);
            }
            current = parent;
        }
        None
    }

    /// Check if the file has web framework imports (actix, axum, rocket)
    fn has_web_framework_context(content: &str) -> bool {
        content.contains("actix_web")
            || content.contains("actix-web")
            || content.contains("use axum")
            || content.contains("axum::")
            || content.contains("use rocket")
            || content.contains("rocket::")
            || content.contains("#[get(")
            || content.contains("#[post(")
            || content.contains("#[put(")
            || content.contains("#[delete(")
    }

    /// Check if the function is a web handler
    fn is_handler_function(func_node: &Node, content: &str) -> bool {
        Self::has_handler_attribute(func_node, content)
            || Self::has_handler_return_type(func_node, content)
    }
}

impl Rule for UnwrapInHandlerRule {
    fn id(&self) -> &str {
        "rust/unwrap-in-handler"
    }

    fn description(&self) -> &str {
        "Detects .unwrap() and .expect() calls in web framework handlers where panics crash the server"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Rust
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Quick check: only analyze files with web framework context
        if !Self::has_web_framework_context(&parsed.content) {
            return findings;
        }

        let mut cursor = parsed.tree.walk();

        find_nodes_by_kind(&mut cursor, "call_expression", |node: Node| {
            if let Some(func) = node.child(0) {
                // Check if this is an .unwrap() or .expect() call
                if func.kind() == "field_expression" {
                    let func_text = func.utf8_text(parsed.content.as_bytes()).unwrap_or("");

                    if func_text.ends_with(".unwrap") || func_text.ends_with(".expect") {
                        // Skip if inside a closure
                        if Self::is_in_closure(&node) {
                            return;
                        }

                        // Find the enclosing function
                        if let Some(enclosing_func) = Self::find_enclosing_function(&node) {
                            // Skip test functions
                            if Self::is_test_context(&enclosing_func, &parsed.content) {
                                return;
                            }

                            // Skip main function
                            if Self::is_main_function(&enclosing_func, &parsed.content) {
                                return;
                            }

                            // Determine if this is a handler function
                            let is_handler =
                                Self::is_handler_function(&enclosing_func, &parsed.content);

                            if is_handler {
                                let method = if func_text.ends_with(".unwrap") {
                                    ".unwrap()"
                                } else {
                                    ".expect()"
                                };
                                let func_name = enclosing_func
                                    .child_by_field_name("name")
                                    .and_then(|n| n.utf8_text(parsed.content.as_bytes()).ok())
                                    .unwrap_or("unknown");

                                findings.push(create_finding_with_confidence(
                                    self.id(),
                                    &node,
                                    &parsed.path,
                                    &parsed.content,
                                    Severity::Error,
                                    &format!(
                                        "{} in web handler '{}' - panic will crash the server. \
                                         Use proper error handling with ? or return an error response.",
                                        method, func_name
                                    ),
                                    Language::Rust,
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
    fn test_command_injection_with_dynamic_args() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // This IS command injection: shell mode + dynamic args
        let content = r#"
use std::process::Command;

fn run_shell(user_cmd: &str) {
    Command::new("sh").arg("-c").arg(format!("echo {}", user_cmd)).output().unwrap();
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = CommandInjectionRule;
        let findings = rule.check(&parsed);

        assert!(!findings.is_empty(), "Should detect injection pattern");
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_shell_spawn_without_injection() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // This is NOT injection - just shell spawn with static args
        let content = r#"
use std::process::Command;

fn get_env() {
    Command::new("cmd").creation_flags(123).output().unwrap();
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let injection_rule = CommandInjectionRule;
        let findings = injection_rule.check(&parsed);

        // Should NOT flag as injection (no -c mode, no dynamic args)
        assert!(findings.is_empty(), "Plain shell spawn is not injection");

        // But ShellSpawnRule should flag it as INFO
        let spawn_rule = ShellSpawnRule;
        let spawn_findings = spawn_rule.check(&parsed);
        assert!(!spawn_findings.is_empty(), "Should detect shell spawn");
        assert_eq!(spawn_findings[0].severity, Severity::Info);
    }

    // =========================================================================
    // Tests for UnwrapOnUserInputRule
    // =========================================================================

    #[test]
    fn test_unwrap_on_file_open() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use std::fs::File;

fn read_file(path: &str) {
    let file = File::open(path).unwrap();
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let flow = crate::flow::FlowContext::build(&parsed, Language::Rust);
        let rule = UnwrapOnUserInputRule;
        let findings = rule.check_with_flow(&parsed, &flow);

        assert!(!findings.is_empty(), "Should detect unwrap on File::open");
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].confidence, Confidence::Medium);
    }

    #[test]
    fn test_unwrap_with_error_handling_ok() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // Using ? operator is fine
        let content = r#"
use std::fs::File;
use std::io::Result;

fn read_file(path: &str) -> Result<()> {
    let file = File::open(path)?;
    Ok(())
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let flow = crate::flow::FlowContext::build(&parsed, Language::Rust);
        let rule = UnwrapOnUserInputRule;
        let findings = rule.check_with_flow(&parsed, &flow);

        // Should NOT flag when using ? operator
        assert!(findings.is_empty(), "Should not flag when using ? operator");
    }

    #[test]
    fn test_unwrap_on_network_operation() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use std::net::TcpStream;

fn connect(addr: &str) {
    let stream = TcpStream::connect(addr).unwrap();
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let flow = crate::flow::FlowContext::build(&parsed, Language::Rust);
        let rule = UnwrapOnUserInputRule;
        let findings = rule.check_with_flow(&parsed, &flow);

        assert!(
            !findings.is_empty(),
            "Should detect unwrap on TcpStream::connect"
        );
    }

    // =========================================================================
    // Tests for MissingErrorPropagationRule
    // =========================================================================

    #[test]
    fn test_missing_error_propagation() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
fn process_data(data: &str) -> Result<String, std::io::Error> {
    let parsed = data.parse::<i32>().unwrap();
    Ok(parsed.to_string())
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = MissingErrorPropagationRule;
        let findings = rule.check(&parsed);

        assert!(
            !findings.is_empty(),
            "Should detect unwrap in function returning Result"
        );
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].confidence, Confidence::Low);
    }

    #[test]
    fn test_unwrap_in_closure_ok() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // Unwrap in closure is often acceptable because closures can't always use ?
        let content = r#"
fn process_items(items: Vec<&str>) -> Result<Vec<i32>, std::num::ParseIntError> {
    let result: Vec<i32> = items.iter().map(|s| s.parse().unwrap()).collect();
    Ok(result)
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = MissingErrorPropagationRule;
        let findings = rule.check(&parsed);

        // Should NOT flag unwrap inside closures
        assert!(findings.is_empty(), "Should not flag unwrap in closure");
    }

    #[test]
    fn test_no_warning_for_non_result_function() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // Function doesn't return Result, so unwrap is expected
        let content = r#"
fn process_data(data: &str) -> String {
    let parsed = data.parse::<i32>().unwrap();
    parsed.to_string()
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = MissingErrorPropagationRule;
        let findings = rule.check(&parsed);

        assert!(
            findings.is_empty(),
            "Should not flag unwrap in function not returning Result"
        );
    }

    // =========================================================================
    // Tests for RawSqlQueryRule
    // =========================================================================

    #[test]
    fn test_raw_sql_with_format() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use sqlx;

fn get_user(name: &str) {
    let query = format!("SELECT * FROM users WHERE name = '{}'", name);
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = RawSqlQueryRule;
        let findings = rule.check(&parsed);

        assert!(!findings.is_empty(), "Should detect format! with SQL");
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_parameterized_query_ok() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // Proper parameterized query should not trigger
        let content = r#"
use sqlx;

async fn get_user(pool: &PgPool, name: &str) -> Result<User, sqlx::Error> {
    sqlx::query_as!(User, "SELECT * FROM users WHERE name = $1", name)
        .fetch_one(pool)
        .await
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = RawSqlQueryRule;
        let findings = rule.check(&parsed);

        // Should NOT flag parameterized queries
        assert!(findings.is_empty(), "Should not flag parameterized queries");
    }

    #[test]
    fn test_diesel_sql_query_with_concat() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use diesel;

fn search_users(term: &str) {
    let query = diesel::sql_query(format!("SELECT * FROM users WHERE name LIKE '%{}%'", term));
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = RawSqlQueryRule;
        let findings = rule.check(&parsed);

        assert!(
            !findings.is_empty(),
            "Should detect diesel::sql_query with format!"
        );
    }

    #[test]
    fn test_rusqlite_with_dynamic_string() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use rusqlite::Connection;

fn delete_user(conn: &Connection, user_id: &str) {
    let sql = format!("DELETE FROM users WHERE id = {}", user_id);
    conn.execute(&sql, []).unwrap();
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = RawSqlQueryRule;
        let findings = rule.check(&parsed);

        assert!(
            !findings.is_empty(),
            "Should detect rusqlite execute with format!"
        );
    }

    #[test]
    fn test_no_sql_context_skipped() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // File without SQL imports should be skipped
        let content = r#"
fn format_message(name: &str) {
    let msg = format!("Hello {}!", name);
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = RawSqlQueryRule;
        let findings = rule.check(&parsed);

        assert!(findings.is_empty(), "Should skip files without SQL context");
    }

    // =========================================================================
    // Tests for rule trait implementations
    // =========================================================================

    #[test]
    fn test_unwrap_on_user_input_uses_flow() {
        let rule = UnwrapOnUserInputRule;
        assert!(
            rule.uses_flow(),
            "UnwrapOnUserInputRule should use flow analysis"
        );
    }

    #[test]
    fn test_missing_error_propagation_no_flow() {
        let rule = MissingErrorPropagationRule;
        assert!(
            !rule.uses_flow(),
            "MissingErrorPropagationRule should not require flow analysis"
        );
    }

    #[test]
    fn test_raw_sql_query_no_flow() {
        let rule = RawSqlQueryRule;
        assert!(
            !rule.uses_flow(),
            "RawSqlQueryRule should not require flow analysis"
        );
    }

    // =========================================================================
    // Tests for UnwrapInHandlerRule
    // =========================================================================

    #[test]
    fn test_unwrap_in_actix_handler() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use actix_web::{get, web, HttpResponse};

#[get("/user/{id}")]
async fn get_user(id: web::Path<String>) -> HttpResponse {
    let user_id: i32 = id.parse().unwrap();
    HttpResponse::Ok().body("ok")
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        assert!(
            !findings.is_empty(),
            "Should detect unwrap in actix handler"
        );
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].confidence, Confidence::Medium);
        assert!(findings[0].message.contains("get_user"));
    }

    #[test]
    fn test_unwrap_in_axum_handler() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use axum::{extract::Path, response::IntoResponse};

async fn handler(Path(id): Path<String>) -> impl IntoResponse {
    let user_id: i32 = id.parse().unwrap();
    "ok"
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        assert!(!findings.is_empty(), "Should detect unwrap in axum handler");
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn test_unwrap_in_rocket_handler() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use rocket::get;

#[get("/")]
fn index() -> &'static str {
    let x = something().unwrap();
    "Hello"
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        assert!(
            !findings.is_empty(),
            "Should detect unwrap in rocket handler"
        );
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn test_unwrap_in_test_ok() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // Unwrap in test code is acceptable
        let content = r#"
use actix_web::get;

#[test]
fn test_parse() {
    let result: i32 = "42".parse().unwrap();
    assert_eq!(result, 42);
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        assert!(
            findings.is_empty(),
            "Should NOT flag unwrap in test functions"
        );
    }

    #[test]
    fn test_unwrap_in_main_ok() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // Unwrap in main is acceptable
        let content = r#"
use axum::Router;

fn main() {
    let config = std::fs::read_to_string("config.toml").unwrap();
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        assert!(
            findings.is_empty(),
            "Should NOT flag unwrap in main function"
        );
    }

    #[test]
    fn test_proper_error_propagation_ok() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // Using ? operator is proper error handling
        let content = r#"
use actix_web::{get, web, Error, HttpResponse};

#[get("/user/{id}")]
async fn get_user(id: web::Path<String>) -> Result<HttpResponse, Error> {
    let user_id: i32 = id.parse()?;
    Ok(HttpResponse::Ok().body("ok"))
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        // No unwrap calls in this code, so no findings
        assert!(
            findings.is_empty(),
            "Should NOT flag proper error handling with ?"
        );
    }

    #[test]
    fn test_expect_in_handler() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use actix_web::{post, web, HttpResponse};

#[post("/data")]
async fn post_data(body: web::Json<Data>) -> HttpResponse {
    let x = something().expect("should work");
    HttpResponse::Ok().finish()
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        assert!(!findings.is_empty(), "Should detect .expect() in handler");
        assert!(findings[0].message.contains(".expect()"));
    }

    #[test]
    fn test_unwrap_in_handler_with_http_response_return() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // Handler detected by return type (no attribute)
        let content = r#"
use actix_web::HttpResponse;

async fn handle_request() -> HttpResponse {
    let data = fetch_data().unwrap();
    HttpResponse::Ok().json(data)
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        assert!(
            !findings.is_empty(),
            "Should detect unwrap in function returning HttpResponse"
        );
    }

    #[test]
    fn test_no_web_framework_context_skipped() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // File without web framework imports should be skipped entirely
        let content = r#"
fn process_data(data: &str) -> String {
    data.parse::<i32>().unwrap().to_string()
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        assert!(
            findings.is_empty(),
            "Should skip files without web framework context"
        );
    }

    #[test]
    fn test_unwrap_in_handler_closure_ok() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        // Unwrap in closure within handler - often necessary
        let content = r#"
use actix_web::{get, HttpResponse};

#[get("/users")]
async fn get_users() -> HttpResponse {
    let ids: Vec<i32> = vec!["1", "2", "3"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    HttpResponse::Ok().json(ids)
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        // Closures are excluded because they often can't use ?
        assert!(
            findings.is_empty(),
            "Should NOT flag unwrap in closure within handler"
        );
    }

    #[test]
    fn test_unwrap_in_cfg_test_module_ok() {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);

        let content = r#"
use actix_web::get;

#[cfg(test)]
mod tests {
    fn test_helper() {
        let x = something().unwrap();
    }
}
"#;

        let parsed = parser.parse_file(Path::new("test.rs"), content).unwrap();
        let rule = UnwrapInHandlerRule;
        let findings = rule.check(&parsed);

        assert!(
            findings.is_empty(),
            "Should NOT flag unwrap in #[cfg(test)] module"
        );
    }

    #[test]
    fn test_unwrap_in_handler_rule_no_flow() {
        let rule = UnwrapInHandlerRule;
        assert!(
            !rule.uses_flow(),
            "UnwrapInHandlerRule should not require flow analysis"
        );
    }
}
