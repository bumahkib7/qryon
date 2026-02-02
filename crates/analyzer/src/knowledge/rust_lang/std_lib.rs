//! Rust standard library profile
//!
//! Provides security knowledge for Rust's standard library.
//! This profile is always active as a baseline for any Rust code.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Rust standard library security profile
///
/// This profile covers:
/// - Environment variables as taint sources
/// - Command execution as sinks
/// - File I/O patterns
/// - Dangerous patterns like unwrap on I/O
pub static STD_LIB_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std",
    description: "Rust standard library security patterns",

    // Always active for Rust code - matches any std:: import or common patterns
    detect_imports: &["std::", "use std", "extern crate std"],

    sources: &[
        // Environment variables
        SourceDef {
            name: "env_var",
            pattern: SourceKind::FunctionCall("std::env::var"),
            taint_label: "env_var",
            description: "Environment variable - may contain untrusted data",
        },
        SourceDef {
            name: "env_var_short",
            pattern: SourceKind::FunctionCall("env::var"),
            taint_label: "env_var",
            description: "Environment variable (short path)",
        },
        SourceDef {
            name: "env_var_os",
            pattern: SourceKind::FunctionCall("std::env::var_os"),
            taint_label: "env_var",
            description: "Environment variable as OsString",
        },
        SourceDef {
            name: "env_args",
            pattern: SourceKind::FunctionCall("std::env::args"),
            taint_label: "cli_args",
            description: "Command line arguments - user controlled",
        },
        SourceDef {
            name: "env_args_short",
            pattern: SourceKind::FunctionCall("env::args"),
            taint_label: "cli_args",
            description: "Command line arguments (short path)",
        },
        SourceDef {
            name: "env_args_os",
            pattern: SourceKind::FunctionCall("std::env::args_os"),
            taint_label: "cli_args",
            description: "Command line arguments as OsString",
        },
        // Standard input
        SourceDef {
            name: "stdin",
            pattern: SourceKind::FunctionCall("std::io::stdin"),
            taint_label: "stdin",
            description: "Standard input - user controlled",
        },
        SourceDef {
            name: "stdin_short",
            pattern: SourceKind::FunctionCall("io::stdin"),
            taint_label: "stdin",
            description: "Standard input (short path)",
        },
        // File reading
        SourceDef {
            name: "fs_read_to_string",
            pattern: SourceKind::FunctionCall("std::fs::read_to_string"),
            taint_label: "file_read",
            description: "File contents - may contain untrusted data",
        },
        SourceDef {
            name: "fs_read_to_string_short",
            pattern: SourceKind::FunctionCall("fs::read_to_string"),
            taint_label: "file_read",
            description: "File contents (short path)",
        },
        SourceDef {
            name: "fs_read",
            pattern: SourceKind::FunctionCall("std::fs::read"),
            taint_label: "file_read",
            description: "File contents as bytes",
        },
        SourceDef {
            name: "file_read",
            pattern: SourceKind::MethodOnType {
                type_pattern: "File",
                method: "read",
            },
            taint_label: "file_read",
            description: "Read from file handle",
        },
        SourceDef {
            name: "bufread_lines",
            pattern: SourceKind::MethodOnType {
                type_pattern: "BufReader",
                method: "lines",
            },
            taint_label: "file_read",
            description: "Lines from buffered reader",
        },
        // Network
        SourceDef {
            name: "tcp_stream_read",
            pattern: SourceKind::MethodOnType {
                type_pattern: "TcpStream",
                method: "read",
            },
            taint_label: "network_read",
            description: "Data from TCP connection",
        },
        // Function parameters (conservative)
        SourceDef {
            name: "parameter",
            pattern: SourceKind::Parameter,
            taint_label: "parameter",
            description: "Function parameter - treat as potentially tainted",
        },
    ],

    sinks: &[
        // Command execution - CRITICAL
        SinkDef {
            name: "command_new",
            pattern: SinkKind::FunctionCall("Command::new"),
            rule_id: "rust/command-injection",
            severity: Severity::Critical,
            description: "Command execution with tainted program name",
            cwe: Some("CWE-78"),
        },
        SinkDef {
            name: "command_arg",
            pattern: SinkKind::MethodCall(".arg"),
            rule_id: "rust/command-injection",
            severity: Severity::Critical,
            description: "Command argument from tainted source",
            cwe: Some("CWE-78"),
        },
        SinkDef {
            name: "command_args",
            pattern: SinkKind::MethodCall(".args"),
            rule_id: "rust/command-injection",
            severity: Severity::Critical,
            description: "Command arguments from tainted source",
            cwe: Some("CWE-78"),
        },
        SinkDef {
            name: "process_command",
            pattern: SinkKind::FunctionCall("std::process::Command::new"),
            rule_id: "rust/command-injection",
            severity: Severity::Critical,
            description: "Process command execution",
            cwe: Some("CWE-78"),
        },
        // File operations with tainted paths
        SinkDef {
            name: "fs_write_tainted_path",
            pattern: SinkKind::FunctionCall("std::fs::write"),
            rule_id: "rust/path-traversal",
            severity: Severity::Error,
            description: "File write with tainted path",
            cwe: Some("CWE-22"),
        },
        SinkDef {
            name: "fs_remove",
            pattern: SinkKind::FunctionCall("std::fs::remove_file"),
            rule_id: "rust/path-traversal",
            severity: Severity::Error,
            description: "File deletion with tainted path",
            cwe: Some("CWE-22"),
        },
        SinkDef {
            name: "fs_remove_dir",
            pattern: SinkKind::FunctionCall("std::fs::remove_dir_all"),
            rule_id: "rust/path-traversal",
            severity: Severity::Critical,
            description: "Recursive directory deletion with tainted path",
            cwe: Some("CWE-22"),
        },
        SinkDef {
            name: "file_create",
            pattern: SinkKind::FunctionCall("File::create"),
            rule_id: "rust/path-traversal",
            severity: Severity::Error,
            description: "File creation with tainted path",
            cwe: Some("CWE-22"),
        },
        SinkDef {
            name: "file_open",
            pattern: SinkKind::FunctionCall("File::open"),
            rule_id: "rust/path-traversal",
            severity: Severity::Warning,
            description: "File open with tainted path",
            cwe: Some("CWE-22"),
        },
        // Network with tainted address
        SinkDef {
            name: "tcp_connect",
            pattern: SinkKind::FunctionCall("TcpStream::connect"),
            rule_id: "rust/ssrf",
            severity: Severity::Error,
            description: "TCP connection to tainted address (SSRF)",
            cwe: Some("CWE-918"),
        },
        SinkDef {
            name: "tcp_listener",
            pattern: SinkKind::FunctionCall("TcpListener::bind"),
            rule_id: "rust/network-bind",
            severity: Severity::Warning,
            description: "Network listener binding to tainted address",
            cwe: None,
        },
    ],

    sanitizers: &[
        SanitizerDef {
            name: "shell_escape",
            pattern: SanitizerKind::Function("shell_escape::escape"),
            sanitizes: "shell",
            description: "Escapes shell metacharacters",
        },
        SanitizerDef {
            name: "shell_words_quote",
            pattern: SanitizerKind::Function("shell_words::quote"),
            sanitizes: "shell",
            description: "Quotes shell arguments safely",
        },
        SanitizerDef {
            name: "path_canonicalize",
            pattern: SanitizerKind::MethodCall(".canonicalize"),
            sanitizes: "path",
            description: "Resolves path to canonical form, eliminating traversal",
        },
        SanitizerDef {
            name: "path_strip_prefix",
            pattern: SanitizerKind::MethodCall(".strip_prefix"),
            sanitizes: "path",
            description: "Validates path is within expected prefix",
        },
        SanitizerDef {
            name: "html_escape",
            pattern: SanitizerKind::Function("html_escape::encode_text"),
            sanitizes: "html",
            description: "HTML entity encoding",
        },
        SanitizerDef {
            name: "percent_encode",
            pattern: SanitizerKind::Function("percent_encoding::percent_encode"),
            sanitizes: "url",
            description: "URL percent encoding",
        },
    ],

    safe_patterns: &[
        SafePattern {
            name: "static_command",
            pattern: "Command::new(\"literal\")",
            reason: "Static command name cannot be injected",
        },
        SafePattern {
            name: "checked_path",
            pattern: "path.starts_with(base) && path.canonicalize()",
            reason: "Path validated against base directory",
        },
    ],

    dangerous_patterns: &[
        // Unwrap on I/O operations
        DangerousPattern {
            name: "unwrap_io_result",
            pattern: PatternKind::Regex(r"\.(read|write|open|connect)\([^)]*\)\s*\.\s*unwrap\(\)"),
            rule_id: "rust/unwrap-io",
            severity: Severity::Warning,
            description: ".unwrap() on I/O Result may panic on failure",
            cwe: Some("CWE-248"),
        },
        DangerousPattern {
            name: "expect_in_library",
            pattern: PatternKind::MethodCall(".expect"),
            rule_id: "rust/expect-in-lib",
            severity: Severity::Info,
            description: ".expect() in library code may panic unexpectedly",
            cwe: Some("CWE-248"),
        },
        // Unsafe without safety comment
        DangerousPattern {
            name: "unsafe_no_comment",
            pattern: PatternKind::Missing("SAFETY comment before unsafe"),
            rule_id: "rust/unsafe-no-safety-comment",
            severity: Severity::Warning,
            description: "unsafe block without SAFETY comment explaining invariants",
            cwe: None,
        },
        // Transmute
        DangerousPattern {
            name: "transmute",
            pattern: PatternKind::MethodCall("std::mem::transmute"),
            rule_id: "rust/transmute",
            severity: Severity::Error,
            description: "std::mem::transmute bypasses type safety",
            cwe: Some("CWE-704"),
        },
        DangerousPattern {
            name: "transmute_short",
            pattern: PatternKind::MethodCall("mem::transmute"),
            rule_id: "rust/transmute",
            severity: Severity::Error,
            description: "mem::transmute bypasses type safety",
            cwe: Some("CWE-704"),
        },
        // Raw pointer dereference
        DangerousPattern {
            name: "raw_ptr_deref",
            pattern: PatternKind::Construct("*ptr where ptr: *const T or *mut T"),
            rule_id: "rust/raw-pointer-deref",
            severity: Severity::Warning,
            description: "Raw pointer dereference requires manual safety guarantees",
            cwe: Some("CWE-476"),
        },
        // Format string in panic
        DangerousPattern {
            name: "panic_format",
            pattern: PatternKind::MacroInvocation("panic!(format!(...))"),
            rule_id: "rust/panic-format",
            severity: Severity::Info,
            description: "panic! with format! is inefficient, use panic!(\"{}\", ...) directly",
            cwe: None,
        },
    ],

    resource_types: &[
        ResourceType {
            name: "File",
            acquire_pattern: "File::open, File::create",
            release_pattern: "Drop (automatic)",
            leak_consequence: "File descriptor leak",
        },
        ResourceType {
            name: "MutexGuard",
            acquire_pattern: "Mutex::lock",
            release_pattern: "Drop (automatic)",
            leak_consequence: "Deadlock if guard not dropped",
        },
        ResourceType {
            name: "RwLockReadGuard",
            acquire_pattern: "RwLock::read",
            release_pattern: "Drop (automatic)",
            leak_consequence: "Blocks writers indefinitely",
        },
        ResourceType {
            name: "RwLockWriteGuard",
            acquire_pattern: "RwLock::write",
            release_pattern: "Drop (automatic)",
            leak_consequence: "Blocks all access indefinitely",
        },
        ResourceType {
            name: "TcpStream",
            acquire_pattern: "TcpStream::connect",
            release_pattern: "Drop (automatic) or .shutdown()",
            leak_consequence: "Connection/socket leak",
        },
        ResourceType {
            name: "TcpListener",
            acquire_pattern: "TcpListener::bind",
            release_pattern: "Drop (automatic)",
            leak_consequence: "Port remains bound",
        },
    ],
};

// Extend PatternKind with MacroInvocation variant used here
impl PatternKind {
    /// Create a macro invocation pattern (helper for construction)
    #[allow(non_snake_case)]
    pub const fn MacroInvocation(pattern: &'static str) -> PatternKind {
        PatternKind::Regex(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_std_profile_basics() {
        assert_eq!(STD_LIB_PROFILE.name, "std");
        assert!(!STD_LIB_PROFILE.sources.is_empty());
        assert!(!STD_LIB_PROFILE.sinks.is_empty());
        assert!(!STD_LIB_PROFILE.dangerous_patterns.is_empty());
    }

    #[test]
    fn test_std_profile_detection() {
        assert!(STD_LIB_PROFILE.is_active("use std::process::Command;"));
        assert!(STD_LIB_PROFILE.is_active("use std::env;"));
    }

    #[test]
    fn test_env_var_sources() {
        let env_sources: Vec<_> = STD_LIB_PROFILE
            .sources
            .iter()
            .filter(|s| s.taint_label == "env_var")
            .collect();
        assert!(!env_sources.is_empty(), "Should have env var sources");
    }

    #[test]
    fn test_command_sinks() {
        let cmd_sinks: Vec<_> = STD_LIB_PROFILE
            .sinks
            .iter()
            .filter(|s| s.rule_id.contains("command"))
            .collect();
        assert!(!cmd_sinks.is_empty(), "Should have command injection sinks");
    }
}
