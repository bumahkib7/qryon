//! Node.js core module security knowledge
//!
//! Defines taint sources, sinks, and sanitizers for Node.js core APIs
//! including fs, path, http, child_process, and process modules.
//!
//! NOTE: This module DETECTS security vulnerabilities - it does not contain them.
//! The patterns here are used to identify dangerous code during static analysis.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Node.js core modules security profile
pub static NODE_CORE_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "node-core",
    description: "Node.js core modules including fs, path, http, and child_process",
    detect_imports: &[
        "require('fs')",
        "require('fs/promises')",
        "require('path')",
        "require('http')",
        "require('https')",
        "require('child_process')",
        "require('readline')",
        "require('net')",
        "require('dgram')",
        "require('crypto')",
        "require('os')",
        "from 'fs'",
        "from 'fs/promises'",
        "from 'path'",
        "from 'http'",
        "from 'https'",
        "from 'child_process'",
        "from 'readline'",
        "from 'net'",
        "from 'node:fs'",
        "from 'node:path'",
        "from 'node:child_process'",
        "from 'node:http'",
        "from 'node:https'",
    ],
    sources: &NODE_CORE_SOURCES,
    sinks: &NODE_CORE_SINKS,
    sanitizers: &NODE_CORE_SANITIZERS,
    safe_patterns: &NODE_CORE_SAFE_PATTERNS,
    dangerous_patterns: &NODE_CORE_DANGEROUS_PATTERNS,
    resource_types: &NODE_CORE_RESOURCES,
};

/// Taint sources - where untrusted data enters Node.js applications
static NODE_CORE_SOURCES: [SourceDef; 18] = [
    // Process/environment sources
    SourceDef {
        name: "process.argv",
        pattern: SourceKind::MemberAccess("process.argv"),
        taint_label: "cli_args",
        description: "Command line arguments - attacker controlled if exposed",
    },
    SourceDef {
        name: "process.env",
        pattern: SourceKind::MemberAccess("process.env"),
        taint_label: "env_var",
        description: "Environment variables - may contain sensitive or untrusted data",
    },
    SourceDef {
        name: "process.stdin",
        pattern: SourceKind::MemberAccess("process.stdin"),
        taint_label: "stdin",
        description: "Standard input stream - user controlled data",
    },
    // File system sources
    SourceDef {
        name: "fs.readFileSync",
        pattern: SourceKind::FunctionCall("fs.readFileSync"),
        taint_label: "file_content",
        description: "Synchronous file read - content may be untrusted",
    },
    SourceDef {
        name: "fs.readFile",
        pattern: SourceKind::FunctionCall("fs.readFile"),
        taint_label: "file_content",
        description: "Async file read - content may be untrusted",
    },
    SourceDef {
        name: "fs.promises.readFile",
        pattern: SourceKind::FunctionCall("fs.promises.readFile"),
        taint_label: "file_content",
        description: "Promise-based file read - content may be untrusted",
    },
    SourceDef {
        name: "fs.createReadStream",
        pattern: SourceKind::FunctionCall("fs.createReadStream"),
        taint_label: "file_content",
        description: "File read stream - content may be untrusted",
    },
    // Readline sources
    SourceDef {
        name: "readline.question",
        pattern: SourceKind::FunctionCall("readline.question"),
        taint_label: "user_input",
        description: "Interactive user input from terminal",
    },
    SourceDef {
        name: "rl.question",
        pattern: SourceKind::MethodOnType {
            type_pattern: "ReadlineInterface",
            method: "question",
        },
        taint_label: "user_input",
        description: "Readline interface question - user input",
    },
    // HTTP sources
    SourceDef {
        name: "req.url",
        pattern: SourceKind::MemberAccess("req.url"),
        taint_label: "url_data",
        description: "HTTP request URL - attacker controlled",
    },
    SourceDef {
        name: "req.headers",
        pattern: SourceKind::MemberAccess("req.headers"),
        taint_label: "http_headers",
        description: "HTTP request headers - attacker controlled",
    },
    SourceDef {
        name: "request.url",
        pattern: SourceKind::MemberAccess("request.url"),
        taint_label: "url_data",
        description: "HTTP request URL - attacker controlled",
    },
    SourceDef {
        name: "request.headers",
        pattern: SourceKind::MemberAccess("request.headers"),
        taint_label: "http_headers",
        description: "HTTP request headers - attacker controlled",
    },
    // OS sources
    SourceDef {
        name: "os.userInfo",
        pattern: SourceKind::FunctionCall("os.userInfo"),
        taint_label: "system_info",
        description: "User information - may leak sensitive data",
    },
    SourceDef {
        name: "os.hostname",
        pattern: SourceKind::FunctionCall("os.hostname"),
        taint_label: "system_info",
        description: "System hostname - infrastructure information",
    },
    // Network sources
    SourceDef {
        name: "socket.on_data",
        pattern: SourceKind::MethodOnType {
            type_pattern: "Socket",
            method: "on('data')",
        },
        taint_label: "network_data",
        description: "Raw socket data - completely untrusted",
    },
    SourceDef {
        name: "http.get_response",
        pattern: SourceKind::FunctionCall("http.get"),
        taint_label: "http_response",
        description: "HTTP response from external source",
    },
    SourceDef {
        name: "https.get_response",
        pattern: SourceKind::FunctionCall("https.get"),
        taint_label: "http_response",
        description: "HTTPS response from external source",
    },
];

/// Dangerous sinks - where tainted data can cause harm
/// NOTE: These patterns are used to DETECT vulnerabilities, not to exploit them
static NODE_CORE_SINKS: [SinkDef; 18] = [
    // Command injection sinks - DETECTION patterns
    SinkDef {
        name: "child_process.exec",
        pattern: SinkKind::FunctionCall("exec"),
        rule_id: "node/command-injection",
        severity: Severity::Critical,
        description: "Detects shell command execution - potential command injection",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "child_process.execSync",
        pattern: SinkKind::FunctionCall("execSync"),
        rule_id: "node/command-injection",
        severity: Severity::Critical,
        description: "Detects sync shell command execution - potential command injection",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "child_process.spawn_shell",
        pattern: SinkKind::FunctionCall("spawn"),
        rule_id: "node/command-injection",
        severity: Severity::Warning,
        description: "Detects process spawn - check shell option and arguments",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "child_process.spawnSync",
        pattern: SinkKind::FunctionCall("spawnSync"),
        rule_id: "node/command-injection",
        severity: Severity::Warning,
        description: "Detects sync process spawn - check shell option and arguments",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "child_process.fork",
        pattern: SinkKind::FunctionCall("fork"),
        rule_id: "node/code-injection",
        severity: Severity::Error,
        description: "Detects fork - verify module path is safe",
        cwe: Some("CWE-94"),
    },
    // Code execution sinks - DETECTION patterns
    SinkDef {
        name: "eval",
        pattern: SinkKind::FunctionCall("eval"),
        rule_id: "node/code-injection",
        severity: Severity::Critical,
        description: "Detects dynamic code execution - extremely dangerous",
        cwe: Some("CWE-94"),
    },
    SinkDef {
        name: "Function_constructor",
        pattern: SinkKind::FunctionCall("Function"),
        rule_id: "node/code-injection",
        severity: Severity::Critical,
        description: "Detects dynamic function creation - code injection risk",
        cwe: Some("CWE-94"),
    },
    SinkDef {
        name: "vm.runInContext",
        pattern: SinkKind::FunctionCall("runInContext"),
        rule_id: "node/code-injection",
        severity: Severity::Critical,
        description: "Detects VM code execution - sandbox escapes possible",
        cwe: Some("CWE-94"),
    },
    SinkDef {
        name: "vm.runInNewContext",
        pattern: SinkKind::FunctionCall("runInNewContext"),
        rule_id: "node/code-injection",
        severity: Severity::Critical,
        description: "Detects VM code execution in new context",
        cwe: Some("CWE-94"),
    },
    SinkDef {
        name: "vm.runInThisContext",
        pattern: SinkKind::FunctionCall("runInThisContext"),
        rule_id: "node/code-injection",
        severity: Severity::Critical,
        description: "Detects VM code execution in current context",
        cwe: Some("CWE-94"),
    },
    // Path traversal sinks - DETECTION patterns
    SinkDef {
        name: "fs.writeFileSync",
        pattern: SinkKind::FunctionCall("writeFileSync"),
        rule_id: "node/path-traversal",
        severity: Severity::Error,
        description: "Detects file write - verify path is within allowed directory",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "fs.writeFile",
        pattern: SinkKind::FunctionCall("writeFile"),
        rule_id: "node/path-traversal",
        severity: Severity::Error,
        description: "Detects async file write - verify path is within allowed directory",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "fs.unlinkSync",
        pattern: SinkKind::FunctionCall("unlinkSync"),
        rule_id: "node/path-traversal",
        severity: Severity::Error,
        description: "Detects file deletion - verify path is safe",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "fs.rmSync",
        pattern: SinkKind::FunctionCall("rmSync"),
        rule_id: "node/path-traversal",
        severity: Severity::Critical,
        description: "Detects recursive deletion - extremely dangerous with tainted path",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "fs.createWriteStream",
        pattern: SinkKind::FunctionCall("createWriteStream"),
        rule_id: "node/path-traversal",
        severity: Severity::Error,
        description: "Detects file write stream - verify path is safe",
        cwe: Some("CWE-22"),
    },
    // Require injection - DETECTION patterns
    SinkDef {
        name: "require_dynamic",
        pattern: SinkKind::FunctionCall("require"),
        rule_id: "node/require-injection",
        severity: Severity::Critical,
        description: "Detects dynamic require - arbitrary code execution possible",
        cwe: Some("CWE-94"),
    },
    SinkDef {
        name: "import_dynamic",
        pattern: SinkKind::FunctionCall("import"),
        rule_id: "node/import-injection",
        severity: Severity::Critical,
        description: "Detects dynamic import - arbitrary code execution possible",
        cwe: Some("CWE-94"),
    },
    // HTTP response sinks - DETECTION patterns
    SinkDef {
        name: "res.write",
        pattern: SinkKind::MethodCall("write"),
        rule_id: "node/xss",
        severity: Severity::Warning,
        description: "Detects HTTP response write - potential XSS if HTML",
        cwe: Some("CWE-79"),
    },
];

/// Sanitizers - functions that neutralize tainted data
static NODE_CORE_SANITIZERS: [SanitizerDef; 8] = [
    SanitizerDef {
        name: "path.basename",
        pattern: SanitizerKind::Function("path.basename"),
        sanitizes: "path_traversal",
        description: "Extracts filename, removing directory components",
    },
    SanitizerDef {
        name: "path.normalize",
        pattern: SanitizerKind::Function("path.normalize"),
        sanitizes: "path",
        description: "Normalizes path, but does NOT prevent traversal",
    },
    SanitizerDef {
        name: "path.resolve",
        pattern: SanitizerKind::Function("path.resolve"),
        sanitizes: "path_partial",
        description: "Resolves to absolute path - use with realpath for full safety",
    },
    SanitizerDef {
        name: "encodeURIComponent",
        pattern: SanitizerKind::Function("encodeURIComponent"),
        sanitizes: "url_component",
        description: "URL-encodes string for safe URL inclusion",
    },
    SanitizerDef {
        name: "shell-escape",
        pattern: SanitizerKind::Function("shellEscape"),
        sanitizes: "shell",
        description: "Escapes string for safe shell inclusion (from shell-escape package)",
    },
    SanitizerDef {
        name: "shell-quote.quote",
        pattern: SanitizerKind::Function("quote"),
        sanitizes: "shell",
        description: "Quotes array for safe shell execution (from shell-quote package)",
    },
    SanitizerDef {
        name: "parseInt",
        pattern: SanitizerKind::Function("parseInt"),
        sanitizes: "numeric",
        description: "Parses to integer - removes non-numeric content",
    },
    SanitizerDef {
        name: "Number",
        pattern: SanitizerKind::Function("Number"),
        sanitizes: "numeric",
        description: "Converts to number - removes non-numeric content",
    },
];

/// Safe patterns - code patterns that are inherently safe
static NODE_CORE_SAFE_PATTERNS: [SafePattern; 5] = [
    SafePattern {
        name: "execFile_no_shell",
        pattern: "execFile",
        reason: "execFile without shell option does not interpret shell metacharacters",
    },
    SafePattern {
        name: "spawn_no_shell",
        pattern: "spawn(..., { shell: false })",
        reason: "spawn without shell option passes arguments directly to process",
    },
    SafePattern {
        name: "constant_require",
        pattern: "require('literal-string')",
        reason: "Static require with literal string is safe",
    },
    SafePattern {
        name: "realpath_check",
        pattern: "fs.realpathSync",
        reason: "Resolves symlinks and can be used to validate path is within bounds",
    },
    SafePattern {
        name: "path_join_validated",
        pattern: "path.join(baseDir, path.basename(userInput))",
        reason: "Using basename removes directory traversal attempts",
    },
];

/// Dangerous patterns - code patterns that indicate potential issues
/// NOTE: These patterns are used to DETECT vulnerabilities during static analysis
static NODE_CORE_DANGEROUS_PATTERNS: [DangerousPattern; 7] = [
    DangerousPattern {
        name: "shell_true",
        pattern: PatternKind::Construct("{ shell: true }"),
        rule_id: "node/shell-spawn",
        severity: Severity::Warning,
        description: "Detects spawn/exec with shell: true - enables shell metacharacter interpretation",
        cwe: Some("CWE-78"),
    },
    DangerousPattern {
        name: "template_in_exec",
        pattern: PatternKind::Construct("exec(`...${...}...`)"),
        rule_id: "node/command-injection",
        severity: Severity::Critical,
        description: "Detects template literal in exec - likely command injection",
        cwe: Some("CWE-78"),
    },
    DangerousPattern {
        name: "concat_in_exec",
        pattern: PatternKind::Regex(r#"exec\s*\([^)]*\+[^)]*\)"#),
        rule_id: "node/command-injection",
        severity: Severity::Critical,
        description: "Detects string concatenation in exec - likely command injection",
        cwe: Some("CWE-78"),
    },
    DangerousPattern {
        name: "dynamic_require",
        pattern: PatternKind::Construct("require(variable)"),
        rule_id: "node/require-injection",
        severity: Severity::Critical,
        description: "Detects dynamic require - arbitrary code execution possible",
        cwe: Some("CWE-94"),
    },
    DangerousPattern {
        name: "unsanitized_path_join",
        pattern: PatternKind::Construct("path.join(base, userInput)"),
        rule_id: "node/path-traversal",
        severity: Severity::Warning,
        description: "Detects path.join with unvalidated input - does not prevent ../ traversal",
        cwe: Some("CWE-22"),
    },
    DangerousPattern {
        name: "eval_json",
        pattern: PatternKind::Regex(r#"eval\s*\(\s*['"`]\s*\(\s*['"`]\s*\+\s*"#),
        rule_id: "node/json-eval",
        severity: Severity::Critical,
        description: "Detects eval for JSON parsing - use JSON.parse instead",
        cwe: Some("CWE-94"),
    },
    DangerousPattern {
        name: "sync_in_async",
        pattern: PatternKind::MethodCall("Sync"),
        rule_id: "node/sync-in-async",
        severity: Severity::Warning,
        description: "Detects synchronous operation that may block event loop",
        cwe: None,
    },
];

/// Resource types that need proper lifecycle management
static NODE_CORE_RESOURCES: [ResourceType; 4] = [
    ResourceType {
        name: "FileHandle",
        acquire_pattern: "fs.promises.open",
        release_pattern: ".close()",
        leak_consequence: "File descriptor leak - may hit ulimit",
    },
    ResourceType {
        name: "ReadStream",
        acquire_pattern: "fs.createReadStream",
        release_pattern: ".destroy() or .close()",
        leak_consequence: "Open file handle - memory and fd leak",
    },
    ResourceType {
        name: "WriteStream",
        acquire_pattern: "fs.createWriteStream",
        release_pattern: ".end() or .destroy()",
        leak_consequence: "Open file handle - data may not flush",
    },
    ResourceType {
        name: "Socket",
        acquire_pattern: "net.createConnection",
        release_pattern: ".end() or .destroy()",
        leak_consequence: "Socket leak - connection exhaustion",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_detection() {
        assert!(NODE_CORE_PROFILE.is_active("const fs = require('fs');"));
        assert!(NODE_CORE_PROFILE.is_active("import fs from 'fs';"));
        assert!(NODE_CORE_PROFILE.is_active("import { exec } from 'child_process';"));
        assert!(NODE_CORE_PROFILE.is_active("import path from 'node:path';"));
        assert!(!NODE_CORE_PROFILE.is_active("import express from 'express';"));
    }

    #[test]
    fn test_sources() {
        assert!(!NODE_CORE_SOURCES.is_empty());
        assert!(NODE_CORE_SOURCES.iter().any(|s| s.name == "process.argv"));
        assert!(NODE_CORE_SOURCES.iter().any(|s| s.name == "process.env"));
    }

    #[test]
    fn test_sinks() {
        assert!(!NODE_CORE_SINKS.is_empty());
        assert!(NODE_CORE_SINKS.iter().any(|s| s.name == "eval"));
        assert!(
            NODE_CORE_SINKS
                .iter()
                .any(|s| s.name == "child_process.exec")
        );
    }

    #[test]
    fn test_sanitizers() {
        assert!(!NODE_CORE_SANITIZERS.is_empty());
        assert!(
            NODE_CORE_SANITIZERS
                .iter()
                .any(|s| s.name == "path.basename")
        );
    }
}
