//! Flask framework security profile
//!
//! Flask is a lightweight WSGI web framework for Python. This profile defines
//! security-relevant patterns for taint analysis including:
//! - Sources: request.args, request.form, request.json, etc.
//! - Sinks: render_template_string (SSTI), Markup, make_response
//! - Sanitizers: Jinja2 auto-escaping, markupsafe.escape, bleach.clean
//!
//! NOTE: This module DETECTS insecure patterns - it does not implement them.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Flask framework profile
pub static FLASK_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "flask",
    description: "Flask - Lightweight WSGI web application framework",
    detect_imports: &["flask", "from flask", "import flask", "from flask import"],
    sources: FLASK_SOURCES,
    sinks: FLASK_SINKS,
    sanitizers: FLASK_SANITIZERS,
    safe_patterns: FLASK_SAFE_PATTERNS,
    dangerous_patterns: FLASK_DANGEROUS_PATTERNS,
    resource_types: FLASK_RESOURCE_TYPES,
};

/// Flask taint sources - where untrusted user input enters the application
static FLASK_SOURCES: &[SourceDef] = &[
    // Query string parameters
    SourceDef {
        name: "request.args",
        pattern: SourceKind::MemberAccess("request.args"),
        taint_label: "user_input",
        description: "Query string parameters from URL (?key=value)",
    },
    SourceDef {
        name: "request.args.get",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.args",
            method: "get",
        },
        taint_label: "user_input",
        description: "Single query string parameter",
    },
    SourceDef {
        name: "request.args.getlist",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.args",
            method: "getlist",
        },
        taint_label: "user_input",
        description: "List of query string parameters with same key",
    },
    // Form data
    SourceDef {
        name: "request.form",
        pattern: SourceKind::MemberAccess("request.form"),
        taint_label: "user_input",
        description: "POST form data",
    },
    SourceDef {
        name: "request.form.get",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.form",
            method: "get",
        },
        taint_label: "user_input",
        description: "Single form field value",
    },
    // JSON data
    SourceDef {
        name: "request.json",
        pattern: SourceKind::MemberAccess("request.json"),
        taint_label: "user_input",
        description: "Parsed JSON request body",
    },
    SourceDef {
        name: "request.get_json",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request",
            method: "get_json",
        },
        taint_label: "user_input",
        description: "Parsed JSON request body via method",
    },
    // Raw data
    SourceDef {
        name: "request.data",
        pattern: SourceKind::MemberAccess("request.data"),
        taint_label: "user_input",
        description: "Raw request body as bytes",
    },
    SourceDef {
        name: "request.get_data",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request",
            method: "get_data",
        },
        taint_label: "user_input",
        description: "Raw request body via method",
    },
    // Headers
    SourceDef {
        name: "request.headers",
        pattern: SourceKind::MemberAccess("request.headers"),
        taint_label: "user_input",
        description: "HTTP request headers (can be spoofed)",
    },
    SourceDef {
        name: "request.headers.get",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.headers",
            method: "get",
        },
        taint_label: "user_input",
        description: "Single HTTP header value",
    },
    // Cookies
    SourceDef {
        name: "request.cookies",
        pattern: SourceKind::MemberAccess("request.cookies"),
        taint_label: "user_input",
        description: "HTTP cookies (client-controlled)",
    },
    SourceDef {
        name: "request.cookies.get",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.cookies",
            method: "get",
        },
        taint_label: "user_input",
        description: "Single cookie value",
    },
    // File uploads
    SourceDef {
        name: "request.files",
        pattern: SourceKind::MemberAccess("request.files"),
        taint_label: "user_input",
        description: "Uploaded files",
    },
    SourceDef {
        name: "request.files.get",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.files",
            method: "get",
        },
        taint_label: "user_input",
        description: "Single uploaded file",
    },
    SourceDef {
        name: "file.filename",
        pattern: SourceKind::MemberAccess("filename"),
        taint_label: "user_input",
        description: "Uploaded file name (user-controlled, dangerous for path operations)",
    },
    // Combined multi-dict
    SourceDef {
        name: "request.values",
        pattern: SourceKind::MemberAccess("request.values"),
        taint_label: "user_input",
        description: "Combined args and form data",
    },
    // URL path
    SourceDef {
        name: "request.path",
        pattern: SourceKind::MemberAccess("request.path"),
        taint_label: "user_input",
        description: "URL path (can contain user input via routing)",
    },
    SourceDef {
        name: "request.full_path",
        pattern: SourceKind::MemberAccess("request.full_path"),
        taint_label: "user_input",
        description: "Full URL path including query string",
    },
    SourceDef {
        name: "request.url",
        pattern: SourceKind::MemberAccess("request.url"),
        taint_label: "user_input",
        description: "Complete request URL",
    },
    // View arguments from URL routing
    SourceDef {
        name: "request.view_args",
        pattern: SourceKind::MemberAccess("request.view_args"),
        taint_label: "user_input",
        description: "Arguments captured from URL routing rules",
    },
    // Stream access
    SourceDef {
        name: "request.stream",
        pattern: SourceKind::MemberAccess("request.stream"),
        taint_label: "user_input",
        description: "Raw input stream",
    },
];

/// Flask taint sinks - dangerous operations where tainted data should not flow
static FLASK_SINKS: &[SinkDef] = &[
    // Server-Side Template Rendering with user strings (SSTI) - CRITICAL
    SinkDef {
        name: "render_template_string",
        pattern: SinkKind::FunctionCall("render_template_string"),
        rule_id: "flask/ssti-render-template-string",
        severity: Severity::Critical,
        description: "render_template_string() with user input allows Server-Side Template attacks (SSTI). Attackers can run arbitrary Python code.",
        cwe: Some("CWE-94"),
    },
    SinkDef {
        name: "Template",
        pattern: SinkKind::FunctionCall("Template"),
        rule_id: "flask/ssti-template-constructor",
        severity: Severity::Critical,
        description: "Jinja2 Template() constructor with user input allows SSTI.",
        cwe: Some("CWE-94"),
    },
    SinkDef {
        name: "Environment.from_string",
        pattern: SinkKind::MethodCall("from_string"),
        rule_id: "flask/ssti-from-string",
        severity: Severity::Critical,
        description: "Jinja2 Environment.from_string() with user input allows SSTI.",
        cwe: Some("CWE-94"),
    },
    // XSS via Markup bypass
    SinkDef {
        name: "Markup",
        pattern: SinkKind::FunctionCall("Markup"),
        rule_id: "flask/xss-markup",
        severity: Severity::Critical,
        description: "Markup() marks strings as safe HTML, bypassing auto-escaping. User input will cause XSS.",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "markupsafe.Markup",
        pattern: SinkKind::FunctionCall("markupsafe.Markup"),
        rule_id: "flask/xss-markupsafe-markup",
        severity: Severity::Critical,
        description: "markupsafe.Markup() marks strings as safe HTML, bypassing auto-escaping.",
        cwe: Some("CWE-79"),
    },
    // Response manipulation
    SinkDef {
        name: "make_response",
        pattern: SinkKind::FunctionCall("make_response"),
        rule_id: "flask/xss-make-response",
        severity: Severity::Error,
        description: "make_response() with tainted content can cause XSS if Content-Type is text/html.",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "Response",
        pattern: SinkKind::FunctionCall("Response"),
        rule_id: "flask/xss-response",
        severity: Severity::Error,
        description: "Response() with tainted content can cause XSS if Content-Type is text/html.",
        cwe: Some("CWE-79"),
    },
    // Open redirect
    SinkDef {
        name: "redirect",
        pattern: SinkKind::FunctionCall("redirect"),
        rule_id: "flask/open-redirect",
        severity: Severity::Error,
        description: "redirect() with user-controlled URL can cause open redirect attacks.",
        cwe: Some("CWE-601"),
    },
    // Path traversal via send_file
    SinkDef {
        name: "send_file",
        pattern: SinkKind::FunctionCall("send_file"),
        rule_id: "flask/path-traversal-send-file",
        severity: Severity::Critical,
        description: "send_file() with user-controlled path can expose arbitrary files.",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "send_from_directory",
        pattern: SinkKind::FunctionCall("send_from_directory"),
        rule_id: "flask/path-traversal-send-from-directory",
        severity: Severity::Error,
        description: "send_from_directory() with user-controlled filename needs path validation.",
        cwe: Some("CWE-22"),
    },
    // Header issues
    SinkDef {
        name: "response.headers",
        pattern: SinkKind::PropertyAssignment("headers"),
        rule_id: "flask/header-manipulation",
        severity: Severity::Error,
        description: "Setting response headers with user input can cause header manipulation.",
        cwe: Some("CWE-113"),
    },
    // Cookie issues
    SinkDef {
        name: "set_cookie",
        pattern: SinkKind::MethodCall("set_cookie"),
        rule_id: "flask/cookie-manipulation",
        severity: Severity::Warning,
        description: "set_cookie() with user input in name or value needs validation.",
        cwe: Some("CWE-20"),
    },
];

/// Flask sanitizers - functions that neutralize tainted data
static FLASK_SANITIZERS: &[SanitizerDef] = &[
    // Jinja2 auto-escaping (when using render_template with .html files)
    SanitizerDef {
        name: "jinja2_autoescape",
        pattern: SanitizerKind::TemplateEngine("render_template"),
        sanitizes: "html",
        description: "Jinja2 auto-escapes HTML in .html templates by default",
    },
    // Explicit escaping
    SanitizerDef {
        name: "markupsafe.escape",
        pattern: SanitizerKind::Function("markupsafe.escape"),
        sanitizes: "html",
        description: "Escapes HTML special characters",
    },
    SanitizerDef {
        name: "escape",
        pattern: SanitizerKind::Function("escape"),
        sanitizes: "html",
        description: "Flask's escape function (alias for markupsafe.escape)",
    },
    // Bleach library for HTML sanitization
    SanitizerDef {
        name: "bleach.clean",
        pattern: SanitizerKind::Function("bleach.clean"),
        sanitizes: "html",
        description: "Bleach sanitizes HTML, allowing only safe tags/attributes",
    },
    SanitizerDef {
        name: "bleach.linkify",
        pattern: SanitizerKind::Function("bleach.linkify"),
        sanitizes: "html",
        description: "Bleach safely converts URLs to links",
    },
    // URL encoding
    SanitizerDef {
        name: "url_quote",
        pattern: SanitizerKind::Function("werkzeug.urls.url_quote"),
        sanitizes: "url",
        description: "URL-encodes special characters",
    },
    SanitizerDef {
        name: "urllib.parse.quote",
        pattern: SanitizerKind::Function("urllib.parse.quote"),
        sanitizes: "url",
        description: "URL-encodes special characters",
    },
    // Path sanitization
    SanitizerDef {
        name: "secure_filename",
        pattern: SanitizerKind::Function("werkzeug.utils.secure_filename"),
        sanitizes: "path",
        description: "Sanitizes filename for safe filesystem use",
    },
];

/// Flask safe patterns - APIs that are inherently safe
static FLASK_SAFE_PATTERNS: &[SafePattern] = &[
    SafePattern {
        name: "render_template",
        pattern: "render_template('template.html', ...)",
        reason: "render_template() with file path (not string) uses auto-escaping by default",
    },
    SafePattern {
        name: "jsonify",
        pattern: "jsonify(data)",
        reason: "jsonify() returns JSON with proper Content-Type, preventing XSS",
    },
    SafePattern {
        name: "url_for",
        pattern: "url_for('endpoint', ...)",
        reason: "url_for() generates URLs safely with proper encoding",
    },
    SafePattern {
        name: "safe_join",
        pattern: "safe_join(directory, filename)",
        reason: "safe_join() prevents path traversal by validating the result stays within directory",
    },
    SafePattern {
        name: "flask_wtf_csrf",
        pattern: "CSRFProtect(app)",
        reason: "Flask-WTF provides CSRF protection",
    },
    SafePattern {
        name: "session_signed",
        pattern: "session['key'] = value",
        reason: "Flask sessions are cryptographically signed by default",
    },
];

/// Flask dangerous patterns - code patterns that indicate potential issues
static FLASK_DANGEROUS_PATTERNS: &[DangerousPattern] = &[
    DangerousPattern {
        name: "debug_mode_production",
        pattern: PatternKind::Regex(r"app\.run\([^)]*debug\s*=\s*True"),
        rule_id: "flask/debug-mode",
        severity: Severity::Critical,
        description: "Debug mode exposes interactive debugger. Never enable in production.",
        cwe: Some("CWE-489"),
    },
    DangerousPattern {
        name: "hardcoded_secret_key",
        pattern: PatternKind::Regex(r#"app\.secret_key\s*=\s*["'][^"']+["']"#),
        rule_id: "flask/hardcoded-secret-key",
        severity: Severity::Critical,
        description: "Hardcoded secret_key allows session forgery. Use environment variable.",
        cwe: Some("CWE-798"),
    },
    DangerousPattern {
        name: "weak_secret_key",
        pattern: PatternKind::Regex(
            r#"secret_key\s*=\s*["'](dev|development|secret|changeme|test)"#,
        ),
        rule_id: "flask/weak-secret-key",
        severity: Severity::Critical,
        description: "Weak secret_key can be easily guessed. Use a strong random value.",
        cwe: Some("CWE-330"),
    },
    DangerousPattern {
        name: "autoescape_disabled",
        pattern: PatternKind::Regex(r"autoescape\s*=\s*False"),
        rule_id: "flask/autoescape-disabled",
        severity: Severity::Error,
        description: "Disabling Jinja2 autoescape allows XSS vulnerabilities.",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "safe_filter_user_input",
        pattern: PatternKind::Regex(r"\|\s*safe"),
        rule_id: "flask/safe-filter-hint",
        severity: Severity::Warning,
        description: "The |safe filter bypasses auto-escaping. Ensure input is trusted.",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "sql_format_string",
        pattern: PatternKind::Regex(r#"execute\([^)]*%.*request\."#),
        rule_id: "flask/sql-format-string",
        severity: Severity::Critical,
        description: "SQL query built with request data. Use parameterized queries.",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "insecure_session_storage",
        pattern: PatternKind::Regex(r#"SESSION_TYPE\s*=\s*["']filesystem["']"#),
        rule_id: "flask/insecure-session-storage",
        severity: Severity::Warning,
        description: "Filesystem sessions may use insecure serialization. Consider signed cookie sessions.",
        cwe: Some("CWE-502"),
    },
    DangerousPattern {
        name: "cors_allow_all",
        pattern: PatternKind::Regex(r#"CORS\([^)]*origins\s*=\s*["']\*["']"#),
        rule_id: "flask/cors-allow-all",
        severity: Severity::Warning,
        description: "CORS with origins='*' allows any origin. Be explicit about allowed origins.",
        cwe: Some("CWE-346"),
    },
    DangerousPattern {
        name: "no_csrf_protection",
        pattern: PatternKind::Regex(r"WTF_CSRF_ENABLED\s*=\s*False"),
        rule_id: "flask/csrf-disabled",
        severity: Severity::Error,
        description: "CSRF protection disabled. Forms are vulnerable to CSRF attacks.",
        cwe: Some("CWE-352"),
    },
];

/// Flask resource types that need proper lifecycle management
static FLASK_RESOURCE_TYPES: &[ResourceType] = &[
    ResourceType {
        name: "database_connection",
        acquire_pattern: "get_db()",
        release_pattern: "teardown_appcontext",
        leak_consequence: "Database connection leak, pool exhaustion",
    },
    ResourceType {
        name: "file_upload",
        acquire_pattern: "request.files",
        release_pattern: "file.close() or context manager",
        leak_consequence: "File descriptor leak",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flask_detection() {
        assert!(FLASK_PROFILE.is_active("from flask import Flask"));
        assert!(FLASK_PROFILE.is_active("import flask"));
        assert!(!FLASK_PROFILE.is_active("import django"));
    }

    #[test]
    fn test_flask_has_sources() {
        assert!(!FLASK_SOURCES.is_empty());
        assert!(FLASK_SOURCES.iter().any(|s| s.name == "request.args"));
        assert!(FLASK_SOURCES.iter().any(|s| s.name == "request.form"));
        assert!(FLASK_SOURCES.iter().any(|s| s.name == "request.json"));
    }

    #[test]
    fn test_flask_has_critical_sinks() {
        assert!(!FLASK_SINKS.is_empty());
        // SSTI is critical
        assert!(
            FLASK_SINKS
                .iter()
                .any(|s| s.name == "render_template_string" && s.severity == Severity::Critical)
        );
        // Markup bypass is critical
        assert!(
            FLASK_SINKS
                .iter()
                .any(|s| s.name == "Markup" && s.severity == Severity::Critical)
        );
    }

    #[test]
    fn test_flask_has_sanitizers() {
        assert!(!FLASK_SANITIZERS.is_empty());
        assert!(
            FLASK_SANITIZERS
                .iter()
                .any(|s| s.name == "markupsafe.escape")
        );
        assert!(FLASK_SANITIZERS.iter().any(|s| s.name == "bleach.clean"));
    }

    #[test]
    fn test_flask_dangerous_patterns() {
        assert!(!FLASK_DANGEROUS_PATTERNS.is_empty());
        assert!(
            FLASK_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "debug_mode_production")
        );
        assert!(
            FLASK_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "hardcoded_secret_key")
        );
    }

    #[test]
    fn test_flask_safe_patterns() {
        assert!(!FLASK_SAFE_PATTERNS.is_empty());
        assert!(
            FLASK_SAFE_PATTERNS
                .iter()
                .any(|p| p.name == "render_template")
        );
        assert!(FLASK_SAFE_PATTERNS.iter().any(|p| p.name == "jsonify"));
    }
}
