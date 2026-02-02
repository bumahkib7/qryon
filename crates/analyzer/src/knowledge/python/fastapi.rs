//! FastAPI framework security profile
//!
//! FastAPI is a modern, high-performance Python web framework for building APIs.
//! This profile defines security-relevant patterns for taint analysis including:
//! - Sources: Query(), Path(), Body(), Header(), Cookie(), Form(), File()
//! - Sinks: HTMLResponse with tainted content, Jinja2Templates, subprocess
//! - Sanitizers: Pydantic validation, html.escape, bleach.clean
//!
//! NOTE: This module DETECTS insecure patterns - it does not implement them.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// FastAPI framework profile
pub static FASTAPI_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "fastapi",
    description: "FastAPI - Modern, fast web framework for building APIs with Python",
    detect_imports: &[
        "fastapi",
        "from fastapi",
        "import fastapi",
        "from fastapi import",
        "from fastapi.responses",
        "from fastapi.security",
    ],
    sources: FASTAPI_SOURCES,
    sinks: FASTAPI_SINKS,
    sanitizers: FASTAPI_SANITIZERS,
    safe_patterns: FASTAPI_SAFE_PATTERNS,
    dangerous_patterns: FASTAPI_DANGEROUS_PATTERNS,
    resource_types: FASTAPI_RESOURCE_TYPES,
};

/// FastAPI taint sources - where untrusted user input enters the application
static FASTAPI_SOURCES: &[SourceDef] = &[
    // Query parameters
    SourceDef {
        name: "Query",
        pattern: SourceKind::FunctionCall("Query"),
        taint_label: "user_input",
        description: "Query string parameter dependency",
    },
    SourceDef {
        name: "Query()",
        pattern: SourceKind::TypeExtractor("Query"),
        taint_label: "user_input",
        description: "Query parameter type annotation",
    },
    // Path parameters
    SourceDef {
        name: "Path",
        pattern: SourceKind::FunctionCall("Path"),
        taint_label: "user_input",
        description: "URL path parameter dependency",
    },
    SourceDef {
        name: "Path()",
        pattern: SourceKind::TypeExtractor("Path"),
        taint_label: "user_input",
        description: "Path parameter type annotation",
    },
    // Request body
    SourceDef {
        name: "Body",
        pattern: SourceKind::FunctionCall("Body"),
        taint_label: "user_input",
        description: "Request body dependency",
    },
    SourceDef {
        name: "Body()",
        pattern: SourceKind::TypeExtractor("Body"),
        taint_label: "user_input",
        description: "Request body type annotation",
    },
    // Headers
    SourceDef {
        name: "Header",
        pattern: SourceKind::FunctionCall("Header"),
        taint_label: "user_input",
        description: "HTTP header dependency (can be spoofed)",
    },
    SourceDef {
        name: "Header()",
        pattern: SourceKind::TypeExtractor("Header"),
        taint_label: "user_input",
        description: "Header type annotation",
    },
    // Cookies
    SourceDef {
        name: "Cookie",
        pattern: SourceKind::FunctionCall("Cookie"),
        taint_label: "user_input",
        description: "HTTP cookie dependency (client-controlled)",
    },
    SourceDef {
        name: "Cookie()",
        pattern: SourceKind::TypeExtractor("Cookie"),
        taint_label: "user_input",
        description: "Cookie type annotation",
    },
    // Form data
    SourceDef {
        name: "Form",
        pattern: SourceKind::FunctionCall("Form"),
        taint_label: "user_input",
        description: "Form field dependency",
    },
    SourceDef {
        name: "Form()",
        pattern: SourceKind::TypeExtractor("Form"),
        taint_label: "user_input",
        description: "Form field type annotation",
    },
    // File uploads
    SourceDef {
        name: "File",
        pattern: SourceKind::FunctionCall("File"),
        taint_label: "user_input",
        description: "File upload dependency",
    },
    SourceDef {
        name: "UploadFile",
        pattern: SourceKind::TypeExtractor("UploadFile"),
        taint_label: "user_input",
        description: "Uploaded file type annotation",
    },
    SourceDef {
        name: "upload_file.filename",
        pattern: SourceKind::MemberAccess("filename"),
        taint_label: "user_input",
        description: "Uploaded file name (user-controlled)",
    },
    // Raw request access
    SourceDef {
        name: "Request.query_params",
        pattern: SourceKind::MemberAccess("request.query_params"),
        taint_label: "user_input",
        description: "Raw query parameters from Starlette Request",
    },
    SourceDef {
        name: "Request.path_params",
        pattern: SourceKind::MemberAccess("request.path_params"),
        taint_label: "user_input",
        description: "Raw path parameters from Starlette Request",
    },
    SourceDef {
        name: "Request.headers",
        pattern: SourceKind::MemberAccess("request.headers"),
        taint_label: "user_input",
        description: "Raw headers from Starlette Request",
    },
    SourceDef {
        name: "Request.cookies",
        pattern: SourceKind::MemberAccess("request.cookies"),
        taint_label: "user_input",
        description: "Raw cookies from Starlette Request",
    },
    SourceDef {
        name: "Request.body",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request",
            method: "body",
        },
        taint_label: "user_input",
        description: "Raw request body bytes",
    },
    SourceDef {
        name: "Request.json",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request",
            method: "json",
        },
        taint_label: "user_input",
        description: "Parsed JSON from request body",
    },
    SourceDef {
        name: "Request.form",
        pattern: SourceKind::MethodOnType {
            type_pattern: "request",
            method: "form",
        },
        taint_label: "user_input",
        description: "Form data from request",
    },
    // WebSocket data
    SourceDef {
        name: "WebSocket.receive_text",
        pattern: SourceKind::MethodOnType {
            type_pattern: "websocket",
            method: "receive_text",
        },
        taint_label: "user_input",
        description: "WebSocket text message",
    },
    SourceDef {
        name: "WebSocket.receive_json",
        pattern: SourceKind::MethodOnType {
            type_pattern: "websocket",
            method: "receive_json",
        },
        taint_label: "user_input",
        description: "WebSocket JSON message",
    },
    SourceDef {
        name: "WebSocket.receive_bytes",
        pattern: SourceKind::MethodOnType {
            type_pattern: "websocket",
            method: "receive_bytes",
        },
        taint_label: "user_input",
        description: "WebSocket binary message",
    },
];

/// FastAPI taint sinks - dangerous operations where tainted data should not flow
static FASTAPI_SINKS: &[SinkDef] = &[
    // XSS via HTMLResponse
    SinkDef {
        name: "HTMLResponse",
        pattern: SinkKind::FunctionCall("HTMLResponse"),
        rule_id: "fastapi/xss-htmlresponse",
        severity: Severity::Error,
        description: "HTMLResponse() with tainted content can cause XSS. Escape user input.",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "Response_html",
        pattern: SinkKind::FunctionCall("Response"),
        rule_id: "fastapi/xss-response-html",
        severity: Severity::Warning,
        description: "Response() with media_type='text/html' and tainted content can cause XSS.",
        cwe: Some("CWE-79"),
    },
    // Template rendering vulnerabilities
    SinkDef {
        name: "Jinja2Templates.TemplateResponse",
        pattern: SinkKind::MethodCall("TemplateResponse"),
        rule_id: "fastapi/ssti-hint",
        severity: Severity::Warning,
        description: "Ensure template context values are properly escaped. |safe filter bypasses escaping.",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "Template",
        pattern: SinkKind::FunctionCall("Template"),
        rule_id: "fastapi/ssti-template",
        severity: Severity::Critical,
        description: "Jinja2 Template() with user input allows template attacks.",
        cwe: Some("CWE-94"),
    },
    // Open redirect
    SinkDef {
        name: "RedirectResponse",
        pattern: SinkKind::FunctionCall("RedirectResponse"),
        rule_id: "fastapi/open-redirect",
        severity: Severity::Error,
        description: "RedirectResponse() with user-controlled URL can cause open redirect.",
        cwe: Some("CWE-601"),
    },
    // File operations
    SinkDef {
        name: "FileResponse",
        pattern: SinkKind::FunctionCall("FileResponse"),
        rule_id: "fastapi/path-traversal-fileresponse",
        severity: Severity::Error,
        description: "FileResponse() with user-controlled path can expose arbitrary files.",
        cwe: Some("CWE-22"),
    },
    // Process invocation with tainted data
    SinkDef {
        name: "subprocess.run_tainted",
        pattern: SinkKind::FunctionCall("subprocess.run"),
        rule_id: "fastapi/process-invocation-subprocess",
        severity: Severity::Critical,
        description: "subprocess.run() with user input. Use shell=False with argument list.",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "subprocess.Popen_tainted",
        pattern: SinkKind::FunctionCall("subprocess.Popen"),
        rule_id: "fastapi/process-invocation-popen",
        severity: Severity::Critical,
        description: "subprocess.Popen() with user input. Use shell=False with argument list.",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "asyncio.create_subprocess_shell",
        pattern: SinkKind::FunctionCall("asyncio.create_subprocess_shell"),
        rule_id: "fastapi/process-invocation-asyncio-shell",
        severity: Severity::Critical,
        description: "asyncio.create_subprocess_shell() invokes shell. Use create_subprocess_exec().",
        cwe: Some("CWE-78"),
    },
    // SQL execution sinks (taint flows into these)
    SinkDef {
        name: "execute_sql",
        pattern: SinkKind::MethodCall("execute"),
        rule_id: "fastapi/sql-execute-tainted",
        severity: Severity::Critical,
        description: "SQL execute() with tainted data. Use parameterized queries.",
        cwe: Some("CWE-89"),
    },
    // Cookie manipulation
    SinkDef {
        name: "response.set_cookie",
        pattern: SinkKind::MethodCall("set_cookie"),
        rule_id: "fastapi/cookie-manipulation",
        severity: Severity::Warning,
        description: "set_cookie() with user input in name or value needs validation.",
        cwe: Some("CWE-20"),
    },
    // Header manipulation
    SinkDef {
        name: "response.headers",
        pattern: SinkKind::PropertyAssignment("headers"),
        rule_id: "fastapi/header-manipulation",
        severity: Severity::Error,
        description: "Setting response headers with user input can cause header manipulation.",
        cwe: Some("CWE-113"),
    },
];

/// FastAPI sanitizers - functions that neutralize tainted data
static FASTAPI_SANITIZERS: &[SanitizerDef] = &[
    // Pydantic validation
    SanitizerDef {
        name: "pydantic_model",
        pattern: SanitizerKind::Function("BaseModel"),
        sanitizes: "structure",
        description: "Pydantic models validate input structure and types",
    },
    SanitizerDef {
        name: "pydantic_validator",
        pattern: SanitizerKind::Function("validator"),
        sanitizes: "custom",
        description: "Pydantic validators provide custom validation",
    },
    SanitizerDef {
        name: "pydantic_field_validator",
        pattern: SanitizerKind::Function("field_validator"),
        sanitizes: "custom",
        description: "Pydantic v2 field validators provide custom validation",
    },
    // HTML escaping
    SanitizerDef {
        name: "html.escape",
        pattern: SanitizerKind::Function("html.escape"),
        sanitizes: "html",
        description: "Escapes HTML special characters",
    },
    SanitizerDef {
        name: "markupsafe.escape",
        pattern: SanitizerKind::Function("markupsafe.escape"),
        sanitizes: "html",
        description: "Escapes HTML special characters",
    },
    // Bleach sanitization
    SanitizerDef {
        name: "bleach.clean",
        pattern: SanitizerKind::Function("bleach.clean"),
        sanitizes: "html",
        description: "Bleach sanitizes HTML, allowing only safe tags/attributes",
    },
    // Jinja2 auto-escaping
    SanitizerDef {
        name: "jinja2_autoescape",
        pattern: SanitizerKind::TemplateEngine("Jinja2Templates"),
        sanitizes: "html",
        description: "Jinja2 auto-escapes HTML by default",
    },
    // URL encoding
    SanitizerDef {
        name: "urllib.parse.quote",
        pattern: SanitizerKind::Function("urllib.parse.quote"),
        sanitizes: "url",
        description: "URL-encodes special characters",
    },
    // Path sanitization
    SanitizerDef {
        name: "pathlib.Path.resolve",
        pattern: SanitizerKind::MethodCall("resolve"),
        sanitizes: "path",
        description: "Resolves path and prevents traversal when combined with containment check",
    },
];

/// FastAPI safe patterns - APIs that are inherently safe
static FASTAPI_SAFE_PATTERNS: &[SafePattern] = &[
    SafePattern {
        name: "pydantic_model_validation",
        pattern: "def endpoint(data: MyModel)",
        reason: "Pydantic models validate and coerce input automatically",
    },
    SafePattern {
        name: "sqlalchemy_orm",
        pattern: "session.query(Model).filter(...)",
        reason: "SQLAlchemy ORM uses parameterized queries",
    },
    SafePattern {
        name: "sqlmodel_orm",
        pattern: "session.exec(select(Model))",
        reason: "SQLModel uses parameterized queries",
    },
    SafePattern {
        name: "databases_parameterized",
        pattern: "database.execute(query, values)",
        reason: "Databases library with parameterized queries",
    },
    SafePattern {
        name: "json_response",
        pattern: "JSONResponse(content)",
        reason: "JSONResponse returns JSON with proper Content-Type",
    },
    SafePattern {
        name: "oauth2_scheme",
        pattern: "OAuth2PasswordBearer(tokenUrl)",
        reason: "OAuth2 authentication scheme",
    },
    SafePattern {
        name: "security_scopes",
        pattern: "Security(oauth2_scheme, scopes=[...])",
        reason: "Security with scopes for authorization",
    },
    SafePattern {
        name: "depends_injection",
        pattern: "Depends(get_current_user)",
        reason: "Dependency injection for authentication/authorization",
    },
    SafePattern {
        name: "httpx_client",
        pattern: "async with httpx.AsyncClient() as client",
        reason: "Proper async HTTP client with connection management",
    },
];

/// FastAPI dangerous patterns - code patterns that indicate potential issues
static FASTAPI_DANGEROUS_PATTERNS: &[DangerousPattern] = &[
    DangerousPattern {
        name: "debug_mode",
        pattern: PatternKind::Regex(r"app\s*=\s*FastAPI\([^)]*debug\s*=\s*True"),
        rule_id: "fastapi/debug-mode",
        severity: Severity::Error,
        description: "Debug mode should be disabled in production.",
        cwe: Some("CWE-489"),
    },
    DangerousPattern {
        name: "cors_allow_all_origins",
        pattern: PatternKind::Regex(r#"allow_origins\s*=\s*\[["']\*["']\]"#),
        rule_id: "fastapi/cors-allow-all",
        severity: Severity::Warning,
        description: "CORS allow_origins=['*'] allows any origin. Be explicit.",
        cwe: Some("CWE-346"),
    },
    DangerousPattern {
        name: "cors_allow_credentials_with_wildcard",
        pattern: PatternKind::Regex(r"allow_credentials\s*=\s*True.*allow_origins.*\*"),
        rule_id: "fastapi/cors-credentials-wildcard",
        severity: Severity::Error,
        description: "allow_credentials=True with wildcard origin is insecure.",
        cwe: Some("CWE-346"),
    },
    DangerousPattern {
        name: "hardcoded_secret",
        pattern: PatternKind::Regex(r#"SECRET_KEY\s*=\s*["'][^"']+["']"#),
        rule_id: "fastapi/hardcoded-secret",
        severity: Severity::Critical,
        description: "Hardcoded secret key. Use environment variable.",
        cwe: Some("CWE-798"),
    },
    DangerousPattern {
        name: "insecure_jwt_algorithm",
        pattern: PatternKind::Regex(r#"algorithm\s*=\s*["']none["']"#),
        rule_id: "fastapi/insecure-jwt-none",
        severity: Severity::Critical,
        description: "JWT with algorithm='none' has no signature verification.",
        cwe: Some("CWE-347"),
    },
    DangerousPattern {
        name: "jwt_hs256_weak_secret",
        pattern: PatternKind::Regex(r#"HS256.*secret.*=.*["'].{0,16}["']"#),
        rule_id: "fastapi/weak-jwt-secret",
        severity: Severity::Error,
        description: "JWT HS256 secret appears weak. Use at least 256 bits of entropy.",
        cwe: Some("CWE-326"),
    },
    DangerousPattern {
        name: "sql_format_string",
        pattern: PatternKind::Regex(r#"execute\([^)]*(%|\.format|f["'])"#),
        rule_id: "fastapi/sql-format-string",
        severity: Severity::Critical,
        description: "SQL query built with string formatting. Use parameterized queries.",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "shell_true",
        pattern: PatternKind::Regex(r"subprocess\.(run|Popen|call)\([^)]*shell\s*=\s*True"),
        rule_id: "fastapi/shell-true",
        severity: Severity::Critical,
        description: "subprocess with shell=True is vulnerable to shell metacharacter attacks.",
        cwe: Some("CWE-78"),
    },
    DangerousPattern {
        name: "safe_filter",
        pattern: PatternKind::Regex(r"\|\s*safe"),
        rule_id: "fastapi/safe-filter-hint",
        severity: Severity::Warning,
        description: "|safe filter bypasses auto-escaping. Ensure input is trusted.",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "insecure_cookie",
        pattern: PatternKind::Regex(r"set_cookie\([^)]*secure\s*=\s*False"),
        rule_id: "fastapi/insecure-cookie",
        severity: Severity::Warning,
        description: "Cookie with secure=False is sent over HTTP.",
        cwe: Some("CWE-614"),
    },
    DangerousPattern {
        name: "no_httponly_cookie",
        pattern: PatternKind::Regex(r"set_cookie\([^)]*httponly\s*=\s*False"),
        rule_id: "fastapi/no-httponly-cookie",
        severity: Severity::Warning,
        description: "Cookie without HttpOnly flag accessible to JavaScript.",
        cwe: Some("CWE-1004"),
    },
    DangerousPattern {
        name: "timing_attack_password",
        pattern: PatternKind::Regex(r"password\s*==\s*"),
        rule_id: "fastapi/timing-attack-password",
        severity: Severity::Warning,
        description: "String comparison for passwords is vulnerable to timing attacks. Use secrets.compare_digest().",
        cwe: Some("CWE-208"),
    },
    DangerousPattern {
        name: "no_rate_limiting",
        pattern: PatternKind::Missing("slowapi"),
        rule_id: "fastapi/no-rate-limiting-hint",
        severity: Severity::Info,
        description: "Consider adding rate limiting (e.g., slowapi) for API endpoints.",
        cwe: Some("CWE-770"),
    },
];

/// FastAPI resource types that need proper lifecycle management
static FASTAPI_RESOURCE_TYPES: &[ResourceType] = &[
    ResourceType {
        name: "database_session",
        acquire_pattern: "get_db() / SessionLocal()",
        release_pattern: "session.close() or dependency with yield",
        leak_consequence: "Database connection leak, pool exhaustion",
    },
    ResourceType {
        name: "http_client",
        acquire_pattern: "httpx.AsyncClient()",
        release_pattern: "async with or await client.aclose()",
        leak_consequence: "HTTP connection leak",
    },
    ResourceType {
        name: "file_upload",
        acquire_pattern: "UploadFile",
        release_pattern: "await file.close()",
        leak_consequence: "File descriptor leak",
    },
    ResourceType {
        name: "redis_connection",
        acquire_pattern: "aioredis.from_url()",
        release_pattern: "await redis.close()",
        leak_consequence: "Redis connection leak",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fastapi_detection() {
        assert!(FASTAPI_PROFILE.is_active("from fastapi import FastAPI"));
        assert!(FASTAPI_PROFILE.is_active("import fastapi"));
        assert!(FASTAPI_PROFILE.is_active("from fastapi.responses import JSONResponse"));
        assert!(!FASTAPI_PROFILE.is_active("from flask import Flask"));
        assert!(!FASTAPI_PROFILE.is_active("from django.http import HttpResponse"));
    }

    #[test]
    fn test_fastapi_has_sources() {
        assert!(!FASTAPI_SOURCES.is_empty());
        assert!(FASTAPI_SOURCES.iter().any(|s| s.name == "Query"));
        assert!(FASTAPI_SOURCES.iter().any(|s| s.name == "Path"));
        assert!(FASTAPI_SOURCES.iter().any(|s| s.name == "Body"));
        assert!(FASTAPI_SOURCES.iter().any(|s| s.name == "Header"));
        assert!(FASTAPI_SOURCES.iter().any(|s| s.name == "Cookie"));
        assert!(FASTAPI_SOURCES.iter().any(|s| s.name == "Form"));
        assert!(FASTAPI_SOURCES.iter().any(|s| s.name == "File"));
    }

    #[test]
    fn test_fastapi_has_sinks() {
        assert!(!FASTAPI_SINKS.is_empty());
        assert!(FASTAPI_SINKS.iter().any(|s| s.name == "HTMLResponse"));
        assert!(FASTAPI_SINKS.iter().any(|s| s.name == "RedirectResponse"));
        assert!(
            FASTAPI_SINKS
                .iter()
                .any(|s| s.name == "subprocess.run_tainted")
        );
    }

    #[test]
    fn test_fastapi_has_sanitizers() {
        assert!(!FASTAPI_SANITIZERS.is_empty());
        assert!(
            FASTAPI_SANITIZERS
                .iter()
                .any(|s| s.name == "pydantic_model")
        );
        assert!(FASTAPI_SANITIZERS.iter().any(|s| s.name == "html.escape"));
        assert!(FASTAPI_SANITIZERS.iter().any(|s| s.name == "bleach.clean"));
    }

    #[test]
    fn test_fastapi_safe_patterns() {
        assert!(!FASTAPI_SAFE_PATTERNS.is_empty());
        assert!(
            FASTAPI_SAFE_PATTERNS
                .iter()
                .any(|p| p.name == "pydantic_model_validation")
        );
        assert!(
            FASTAPI_SAFE_PATTERNS
                .iter()
                .any(|p| p.name == "sqlalchemy_orm")
        );
        assert!(
            FASTAPI_SAFE_PATTERNS
                .iter()
                .any(|p| p.name == "sqlmodel_orm")
        );
    }

    #[test]
    fn test_fastapi_dangerous_patterns() {
        assert!(!FASTAPI_DANGEROUS_PATTERNS.is_empty());
        assert!(
            FASTAPI_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "cors_allow_all_origins")
        );
        assert!(
            FASTAPI_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "hardcoded_secret")
        );
        assert!(
            FASTAPI_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "sql_format_string")
        );
        assert!(
            FASTAPI_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "shell_true")
        );
    }
}
