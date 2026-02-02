//! Django framework security profile
//!
//! Django is a high-level Python web framework that encourages rapid development
//! and clean, pragmatic design. This profile defines security-relevant patterns
//! for taint analysis including:
//! - Sources: request.GET, request.POST, request.body, etc.
//! - Sinks: mark_safe, HttpResponse, cursor.execute with formatting
//! - Sanitizers: Django template auto-escaping, django.utils.html.escape
//!
//! NOTE: This module DETECTS insecure patterns - it does not implement them.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Django framework profile
pub static DJANGO_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "django",
    description: "Django - The web framework for perfectionists with deadlines",
    detect_imports: &[
        "django",
        "from django",
        "import django",
        "from django import",
        "from django.http",
        "from django.shortcuts",
        "from django.views",
    ],
    sources: DJANGO_SOURCES,
    sinks: DJANGO_SINKS,
    sanitizers: DJANGO_SANITIZERS,
    safe_patterns: DJANGO_SAFE_PATTERNS,
    dangerous_patterns: DJANGO_DANGEROUS_PATTERNS,
    resource_types: DJANGO_RESOURCE_TYPES,
};

/// Django taint sources - where untrusted user input enters the application
static DJANGO_SOURCES: &[SourceDef] = &[
    // Query string parameters (GET)
    SourceDef {
        name: "request.GET",
        pattern: SourceKind::MemberAccess("request.GET"),
        taint_label: "user_input",
        description: "Query string parameters from URL",
    },
    SourceDef {
        name: "request.GET.get",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.GET",
            method: "get",
        },
        taint_label: "user_input",
        description: "Single query string parameter",
    },
    SourceDef {
        name: "request.GET.getlist",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.GET",
            method: "getlist",
        },
        taint_label: "user_input",
        description: "List of query string parameters with same key",
    },
    // POST data
    SourceDef {
        name: "request.POST",
        pattern: SourceKind::MemberAccess("request.POST"),
        taint_label: "user_input",
        description: "POST form data",
    },
    SourceDef {
        name: "request.POST.get",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.POST",
            method: "get",
        },
        taint_label: "user_input",
        description: "Single POST parameter",
    },
    // Raw body
    SourceDef {
        name: "request.body",
        pattern: SourceKind::MemberAccess("request.body"),
        taint_label: "user_input",
        description: "Raw request body as bytes",
    },
    // Headers and META
    SourceDef {
        name: "request.META",
        pattern: SourceKind::MemberAccess("request.META"),
        taint_label: "user_input",
        description: "HTTP headers and server variables (can be spoofed)",
    },
    SourceDef {
        name: "request.META.get",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.META",
            method: "get",
        },
        taint_label: "user_input",
        description: "Single header or META value",
    },
    SourceDef {
        name: "request.headers",
        pattern: SourceKind::MemberAccess("request.headers"),
        taint_label: "user_input",
        description: "HTTP request headers (Django 2.2+)",
    },
    // Cookies
    SourceDef {
        name: "request.COOKIES",
        pattern: SourceKind::MemberAccess("request.COOKIES"),
        taint_label: "user_input",
        description: "HTTP cookies (client-controlled)",
    },
    SourceDef {
        name: "request.COOKIES.get",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.COOKIES",
            method: "get",
        },
        taint_label: "user_input",
        description: "Single cookie value",
    },
    // File uploads
    SourceDef {
        name: "request.FILES",
        pattern: SourceKind::MemberAccess("request.FILES"),
        taint_label: "user_input",
        description: "Uploaded files",
    },
    SourceDef {
        name: "request.FILES.get",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request.FILES",
            method: "get",
        },
        taint_label: "user_input",
        description: "Single uploaded file",
    },
    SourceDef {
        name: "uploaded_file.name",
        pattern: SourceKind::MemberAccess("name"),
        taint_label: "user_input",
        description: "Uploaded file name (user-controlled)",
    },
    // URL path
    SourceDef {
        name: "request.path",
        pattern: SourceKind::MemberAccess("request.path"),
        taint_label: "user_input",
        description: "URL path (can contain user input via routing)",
    },
    SourceDef {
        name: "request.path_info",
        pattern: SourceKind::MemberAccess("request.path_info"),
        taint_label: "user_input",
        description: "URL path info",
    },
    SourceDef {
        name: "request.get_full_path",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request",
            method: "get_full_path",
        },
        taint_label: "user_input",
        description: "Full URL path including query string",
    },
    // Class-based view kwargs
    SourceDef {
        name: "self.kwargs",
        pattern: SourceKind::MemberAccess("self.kwargs"),
        taint_label: "user_input",
        description: "URL parameters captured by class-based views",
    },
    SourceDef {
        name: "kwargs",
        pattern: SourceKind::MemberAccess("kwargs"),
        taint_label: "user_input",
        description: "URL parameters passed to view functions",
    },
    // Session (can be user-influenced in some configs)
    SourceDef {
        name: "request.session",
        pattern: SourceKind::MemberAccess("request.session"),
        taint_label: "user_influenced",
        description: "Session data (may contain user-influenced values)",
    },
    // User input from forms
    SourceDef {
        name: "form.cleaned_data",
        pattern: SourceKind::MemberAccess("cleaned_data"),
        taint_label: "validated_input",
        description: "Form data after validation (still user input)",
    },
    // Content type
    SourceDef {
        name: "request.content_type",
        pattern: SourceKind::MemberAccess("request.content_type"),
        taint_label: "user_input",
        description: "Request Content-Type header",
    },
];

/// Django taint sinks - dangerous operations where tainted data should not flow
static DJANGO_SINKS: &[SinkDef] = &[
    // XSS via mark_safe
    SinkDef {
        name: "mark_safe",
        pattern: SinkKind::FunctionCall("mark_safe"),
        rule_id: "django/xss-mark-safe",
        severity: Severity::Critical,
        description: "mark_safe() bypasses Django's auto-escaping. User input will cause XSS.",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "SafeString",
        pattern: SinkKind::FunctionCall("SafeString"),
        rule_id: "django/xss-safestring",
        severity: Severity::Critical,
        description: "SafeString() marks content as safe HTML, bypassing auto-escaping.",
        cwe: Some("CWE-79"),
    },
    // Response with tainted content
    SinkDef {
        name: "HttpResponse",
        pattern: SinkKind::FunctionCall("HttpResponse"),
        rule_id: "django/xss-httpresponse",
        severity: Severity::Error,
        description: "HttpResponse() with tainted content can cause XSS. Use render() with templates.",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "HttpResponseRedirect",
        pattern: SinkKind::FunctionCall("HttpResponseRedirect"),
        rule_id: "django/open-redirect",
        severity: Severity::Error,
        description: "HttpResponseRedirect() with user-controlled URL can cause open redirect.",
        cwe: Some("CWE-601"),
    },
    SinkDef {
        name: "redirect",
        pattern: SinkKind::FunctionCall("redirect"),
        rule_id: "django/open-redirect",
        severity: Severity::Error,
        description: "redirect() with user-controlled URL can cause open redirect attacks.",
        cwe: Some("CWE-601"),
    },
    // SQL execution sinks (taint flows into these)
    SinkDef {
        name: "cursor.execute",
        pattern: SinkKind::MethodCall("execute"),
        rule_id: "django/sql-execute-tainted",
        severity: Severity::Critical,
        description: "cursor.execute() with tainted data. Use parameterized queries: cursor.execute(sql, [params]).",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "raw_query",
        pattern: SinkKind::MethodCall("raw"),
        rule_id: "django/sql-raw-tainted",
        severity: Severity::Critical,
        description: "Model.objects.raw() with tainted data. Use parameterized queries.",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "extra_query",
        pattern: SinkKind::MethodCall("extra"),
        rule_id: "django/sql-extra-tainted",
        severity: Severity::Error,
        description: "QuerySet.extra() with tainted data is dangerous. Prefer ORM methods.",
        cwe: Some("CWE-89"),
    },
    // Template with tainted string
    SinkDef {
        name: "Template",
        pattern: SinkKind::FunctionCall("Template"),
        rule_id: "django/ssti-template",
        severity: Severity::Critical,
        description: "django.template.Template() with user input allows template attacks.",
        cwe: Some("CWE-94"),
    },
    // File operations
    SinkDef {
        name: "FileResponse",
        pattern: SinkKind::FunctionCall("FileResponse"),
        rule_id: "django/path-traversal-fileresponse",
        severity: Severity::Error,
        description: "FileResponse() with user-controlled path can expose arbitrary files.",
        cwe: Some("CWE-22"),
    },
    // Safe filter in templates
    SinkDef {
        name: "safe_filter",
        pattern: SinkKind::TemplateInsertion,
        rule_id: "django/xss-safe-filter",
        severity: Severity::Error,
        description: "|safe filter bypasses auto-escaping. Ensure input is trusted.",
        cwe: Some("CWE-79"),
    },
];

/// Django sanitizers - functions that neutralize tainted data
static DJANGO_SANITIZERS: &[SanitizerDef] = &[
    // Django template auto-escaping
    SanitizerDef {
        name: "django_template_autoescape",
        pattern: SanitizerKind::TemplateEngine("render"),
        sanitizes: "html",
        description: "Django templates auto-escape HTML by default",
    },
    SanitizerDef {
        name: "render_to_string",
        pattern: SanitizerKind::TemplateEngine("render_to_string"),
        sanitizes: "html",
        description: "render_to_string() uses auto-escaping",
    },
    // Explicit escaping
    SanitizerDef {
        name: "django.utils.html.escape",
        pattern: SanitizerKind::Function("django.utils.html.escape"),
        sanitizes: "html",
        description: "Escapes HTML special characters",
    },
    SanitizerDef {
        name: "escape",
        pattern: SanitizerKind::Function("escape"),
        sanitizes: "html",
        description: "Django's escape function",
    },
    SanitizerDef {
        name: "conditional_escape",
        pattern: SanitizerKind::Function("conditional_escape"),
        sanitizes: "html",
        description: "Escapes if not already marked safe",
    },
    // Format HTML safely
    SanitizerDef {
        name: "format_html",
        pattern: SanitizerKind::Function("format_html"),
        sanitizes: "html",
        description: "format_html() escapes arguments before interpolation",
    },
    SanitizerDef {
        name: "format_html_join",
        pattern: SanitizerKind::Function("format_html_join"),
        sanitizes: "html",
        description: "format_html_join() safely joins HTML fragments",
    },
    // URL encoding
    SanitizerDef {
        name: "urlencode",
        pattern: SanitizerKind::Function("django.utils.http.urlencode"),
        sanitizes: "url",
        description: "URL-encodes parameters",
    },
    SanitizerDef {
        name: "urlquote",
        pattern: SanitizerKind::Function("django.utils.http.urlquote"),
        sanitizes: "url",
        description: "URL-encodes special characters",
    },
    // Strip tags (partial sanitization)
    SanitizerDef {
        name: "strip_tags",
        pattern: SanitizerKind::Function("django.utils.html.strip_tags"),
        sanitizes: "html",
        description: "Removes HTML tags (use with caution, not XSS-safe alone)",
    },
    // Bleach for rich text
    SanitizerDef {
        name: "bleach.clean",
        pattern: SanitizerKind::Function("bleach.clean"),
        sanitizes: "html",
        description: "Bleach sanitizes HTML, allowing only safe tags/attributes",
    },
];

/// Django safe patterns - APIs that are inherently safe
static DJANGO_SAFE_PATTERNS: &[SafePattern] = &[
    SafePattern {
        name: "orm_queries",
        pattern: "Model.objects.filter(field=value)",
        reason: "Django ORM queries use parameterized SQL, preventing SQL attacks",
    },
    SafePattern {
        name: "orm_get",
        pattern: "Model.objects.get(pk=value)",
        reason: "Django ORM get() uses parameterized SQL",
    },
    SafePattern {
        name: "cursor_parameterized",
        pattern: "cursor.execute(sql, [params])",
        reason: "Parameterized queries prevent SQL attacks by separating code from data",
    },
    SafePattern {
        name: "raw_parameterized",
        pattern: "Model.objects.raw(sql, [params])",
        reason: "Raw queries with params list are parameterized",
    },
    SafePattern {
        name: "render_template",
        pattern: "render(request, 'template.html', context)",
        reason: "render() with template file uses auto-escaping by default",
    },
    SafePattern {
        name: "json_response",
        pattern: "JsonResponse(data)",
        reason: "JsonResponse returns JSON with proper Content-Type",
    },
    SafePattern {
        name: "form_validation",
        pattern: "form.is_valid()",
        reason: "Django forms provide input validation",
    },
    SafePattern {
        name: "csrf_protection",
        pattern: "@csrf_protect",
        reason: "CSRF protection decorator prevents CSRF attacks",
    },
    SafePattern {
        name: "login_required",
        pattern: "@login_required",
        reason: "Enforces authentication",
    },
    SafePattern {
        name: "permission_required",
        pattern: "@permission_required",
        reason: "Enforces authorization",
    },
];

/// Django dangerous patterns - code patterns that indicate potential issues
static DJANGO_DANGEROUS_PATTERNS: &[DangerousPattern] = &[
    DangerousPattern {
        name: "debug_true",
        pattern: PatternKind::Regex(r"DEBUG\s*=\s*True"),
        rule_id: "django/debug-true",
        severity: Severity::Critical,
        description: "DEBUG=True exposes sensitive information. Disable in production.",
        cwe: Some("CWE-489"),
    },
    DangerousPattern {
        name: "hardcoded_secret_key",
        pattern: PatternKind::Regex(r#"SECRET_KEY\s*=\s*["'][^"']+["']"#),
        rule_id: "django/hardcoded-secret-key",
        severity: Severity::Critical,
        description: "Hardcoded SECRET_KEY. Use environment variable.",
        cwe: Some("CWE-798"),
    },
    DangerousPattern {
        name: "allowed_hosts_wildcard",
        pattern: PatternKind::Regex(r#"ALLOWED_HOSTS\s*=\s*\[["']\*["']\]"#),
        rule_id: "django/allowed-hosts-wildcard",
        severity: Severity::Error,
        description: "ALLOWED_HOSTS=['*'] allows any host. Be explicit.",
        cwe: Some("CWE-16"),
    },
    DangerousPattern {
        name: "csrf_exempt",
        pattern: PatternKind::Regex(r"@csrf_exempt"),
        rule_id: "django/csrf-exempt",
        severity: Severity::Warning,
        description: "@csrf_exempt disables CSRF protection for this view.",
        cwe: Some("CWE-352"),
    },
    DangerousPattern {
        name: "safe_filter",
        pattern: PatternKind::Regex(r"\|\s*safe"),
        rule_id: "django/safe-filter-hint",
        severity: Severity::Warning,
        description: "|safe filter bypasses auto-escaping. Ensure input is trusted.",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "autoescape_off",
        pattern: PatternKind::Regex(r"\{%\s*autoescape\s+off\s*%\}"),
        rule_id: "django/autoescape-off",
        severity: Severity::Error,
        description: "{% autoescape off %} disables auto-escaping in template block.",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "sql_format_string",
        pattern: PatternKind::Regex(r#"\.execute\([^)]*(%|\.format|f["'])"#),
        rule_id: "django/sql-format-string",
        severity: Severity::Critical,
        description: "SQL query built with string formatting. Use parameterized queries.",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "insecure_cookie",
        pattern: PatternKind::Regex(r"SESSION_COOKIE_SECURE\s*=\s*False"),
        rule_id: "django/insecure-session-cookie",
        severity: Severity::Error,
        description: "SESSION_COOKIE_SECURE=False sends session cookie over HTTP.",
        cwe: Some("CWE-614"),
    },
    DangerousPattern {
        name: "insecure_csrf_cookie",
        pattern: PatternKind::Regex(r"CSRF_COOKIE_SECURE\s*=\s*False"),
        rule_id: "django/insecure-csrf-cookie",
        severity: Severity::Error,
        description: "CSRF_COOKIE_SECURE=False sends CSRF cookie over HTTP.",
        cwe: Some("CWE-614"),
    },
    DangerousPattern {
        name: "no_httponly_cookie",
        pattern: PatternKind::Regex(r"SESSION_COOKIE_HTTPONLY\s*=\s*False"),
        rule_id: "django/no-httponly-session",
        severity: Severity::Warning,
        description: "SESSION_COOKIE_HTTPONLY=False allows JavaScript access to session cookie.",
        cwe: Some("CWE-1004"),
    },
    DangerousPattern {
        name: "weak_password_hasher",
        pattern: PatternKind::Regex(r"PASSWORD_HASHERS.*MD5PasswordHasher"),
        rule_id: "django/weak-password-hasher",
        severity: Severity::Critical,
        description: "MD5PasswordHasher is insecure. Use Argon2 or PBKDF2.",
        cwe: Some("CWE-916"),
    },
    DangerousPattern {
        name: "cors_allow_all",
        pattern: PatternKind::Regex(r"CORS_ALLOW_ALL_ORIGINS\s*=\s*True"),
        rule_id: "django/cors-allow-all",
        severity: Severity::Warning,
        description: "CORS_ALLOW_ALL_ORIGINS=True allows any origin.",
        cwe: Some("CWE-346"),
    },
    DangerousPattern {
        name: "shell_plus_insecure",
        pattern: PatternKind::Regex(r"NOTEBOOK_ARGUMENTS.*allow-root"),
        rule_id: "django/shell-plus-insecure",
        severity: Severity::Warning,
        description: "Running Django shell as root is insecure.",
        cwe: Some("CWE-250"),
    },
];

/// Django resource types that need proper lifecycle management
static DJANGO_RESOURCE_TYPES: &[ResourceType] = &[
    ResourceType {
        name: "database_connection",
        acquire_pattern: "connection.cursor()",
        release_pattern: "connection.close() or context manager",
        leak_consequence: "Database connection leak, pool exhaustion",
    },
    ResourceType {
        name: "file_upload",
        acquire_pattern: "request.FILES",
        release_pattern: "file.close() or context manager",
        leak_consequence: "File descriptor leak",
    },
    ResourceType {
        name: "cache_connection",
        acquire_pattern: "cache.get_client()",
        release_pattern: "automatic (pooled)",
        leak_consequence: "Cache connection leak",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_django_detection() {
        assert!(DJANGO_PROFILE.is_active("from django.http import HttpResponse"));
        assert!(DJANGO_PROFILE.is_active("import django"));
        assert!(DJANGO_PROFILE.is_active("from django.shortcuts import render"));
        assert!(!DJANGO_PROFILE.is_active("from flask import Flask"));
    }

    #[test]
    fn test_django_has_sources() {
        assert!(!DJANGO_SOURCES.is_empty());
        assert!(DJANGO_SOURCES.iter().any(|s| s.name == "request.GET"));
        assert!(DJANGO_SOURCES.iter().any(|s| s.name == "request.POST"));
        assert!(DJANGO_SOURCES.iter().any(|s| s.name == "request.body"));
        assert!(DJANGO_SOURCES.iter().any(|s| s.name == "request.META"));
        assert!(DJANGO_SOURCES.iter().any(|s| s.name == "self.kwargs"));
    }

    #[test]
    fn test_django_has_critical_sinks() {
        assert!(!DJANGO_SINKS.is_empty());
        // mark_safe is critical
        assert!(
            DJANGO_SINKS
                .iter()
                .any(|s| s.name == "mark_safe" && s.severity == Severity::Critical)
        );
    }

    #[test]
    fn test_django_has_sanitizers() {
        assert!(!DJANGO_SANITIZERS.is_empty());
        assert!(
            DJANGO_SANITIZERS
                .iter()
                .any(|s| s.name == "django.utils.html.escape")
        );
        assert!(DJANGO_SANITIZERS.iter().any(|s| s.name == "format_html"));
    }

    #[test]
    fn test_django_safe_patterns() {
        assert!(!DJANGO_SAFE_PATTERNS.is_empty());
        assert!(DJANGO_SAFE_PATTERNS.iter().any(|p| p.name == "orm_queries"));
        assert!(
            DJANGO_SAFE_PATTERNS
                .iter()
                .any(|p| p.name == "cursor_parameterized")
        );
    }

    #[test]
    fn test_django_dangerous_patterns() {
        assert!(!DJANGO_DANGEROUS_PATTERNS.is_empty());
        assert!(
            DJANGO_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "debug_true")
        );
        assert!(
            DJANGO_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "hardcoded_secret_key")
        );
        assert!(
            DJANGO_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "sql_format_string")
        );
    }
}
