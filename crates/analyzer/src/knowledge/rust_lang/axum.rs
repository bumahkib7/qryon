//! Axum framework profile
//!
//! Security knowledge for the Axum web framework, built on top of tower
//! and hyper. Covers extractors, responses, and middleware patterns.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Axum framework security profile
///
/// Covers:
/// - Extractors (Query, Path, Json, Form, etc.) as taint sources
/// - HeaderMap and Request<Body> access
/// - Html() response wrapper as XSS sink
/// - Redirect responses with tainted URLs
pub static AXUM_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "axum",
    description: "Axum framework security patterns (tower-based)",

    detect_imports: &["axum", "use axum::", "axum::"],

    sources: &[
        // Extractors - primary taint sources
        SourceDef {
            name: "extract_query",
            pattern: SourceKind::TypeExtractor("axum::extract::Query"),
            taint_label: "user_input",
            description: "Query string parameters",
        },
        SourceDef {
            name: "extract_query_short",
            pattern: SourceKind::TypeExtractor("Query"),
            taint_label: "user_input",
            description: "Query string parameters (short import)",
        },
        SourceDef {
            name: "extract_path",
            pattern: SourceKind::TypeExtractor("axum::extract::Path"),
            taint_label: "user_input",
            description: "URL path parameters",
        },
        SourceDef {
            name: "extract_path_short",
            pattern: SourceKind::TypeExtractor("Path"),
            taint_label: "user_input",
            description: "URL path parameters (short import)",
        },
        SourceDef {
            name: "extract_json",
            pattern: SourceKind::TypeExtractor("axum::extract::Json"),
            taint_label: "user_input",
            description: "JSON request body",
        },
        SourceDef {
            name: "extract_json_short",
            pattern: SourceKind::TypeExtractor("Json"),
            taint_label: "user_input",
            description: "JSON request body (short import)",
        },
        SourceDef {
            name: "extract_form",
            pattern: SourceKind::TypeExtractor("axum::extract::Form"),
            taint_label: "user_input",
            description: "Form data",
        },
        SourceDef {
            name: "extract_form_short",
            pattern: SourceKind::TypeExtractor("Form"),
            taint_label: "user_input",
            description: "Form data (short import)",
        },
        SourceDef {
            name: "extract_raw_body",
            pattern: SourceKind::TypeExtractor("axum::body::Bytes"),
            taint_label: "user_input",
            description: "Raw request body bytes",
        },
        SourceDef {
            name: "extract_body_string",
            pattern: SourceKind::TypeExtractor("String"),
            taint_label: "user_input",
            description: "Request body as String (when used as extractor)",
        },
        // Headers
        SourceDef {
            name: "header_map",
            pattern: SourceKind::TypeExtractor("HeaderMap"),
            taint_label: "http_headers",
            description: "HTTP request headers",
        },
        SourceDef {
            name: "typed_header",
            pattern: SourceKind::TypeExtractor("TypedHeader"),
            taint_label: "http_headers",
            description: "Typed HTTP header",
        },
        SourceDef {
            name: "header_get",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HeaderMap",
                method: "get",
            },
            taint_label: "http_headers",
            description: "Get header value",
        },
        // Request<Body>
        SourceDef {
            name: "request_body",
            pattern: SourceKind::TypeExtractor("Request<Body>"),
            taint_label: "user_input",
            description: "Full HTTP request with body",
        },
        SourceDef {
            name: "request_uri",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Request",
                method: "uri",
            },
            taint_label: "url_data",
            description: "Request URI",
        },
        SourceDef {
            name: "request_headers",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Request",
                method: "headers",
            },
            taint_label: "http_headers",
            description: "Request headers",
        },
        // Multipart
        SourceDef {
            name: "multipart",
            pattern: SourceKind::TypeExtractor("Multipart"),
            taint_label: "user_input",
            description: "Multipart form data (file uploads)",
        },
        SourceDef {
            name: "multipart_field",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Multipart",
                method: "next_field",
            },
            taint_label: "user_input",
            description: "Multipart field data",
        },
        // WebSocket
        SourceDef {
            name: "ws_message",
            pattern: SourceKind::TypeExtractor("ws::Message"),
            taint_label: "user_input",
            description: "WebSocket message from client",
        },
        // Extension / State (can contain user data)
        SourceDef {
            name: "extension",
            pattern: SourceKind::TypeExtractor("Extension"),
            taint_label: "extension",
            description: "Request extension (check if derived from user input)",
        },
        // Cookie
        SourceDef {
            name: "cookie_jar",
            pattern: SourceKind::TypeExtractor("CookieJar"),
            taint_label: "cookie",
            description: "Request cookies",
        },
        SourceDef {
            name: "cookie_get",
            pattern: SourceKind::MethodOnType {
                type_pattern: "CookieJar",
                method: "get",
            },
            taint_label: "cookie",
            description: "Get cookie value",
        },
    ],

    sinks: &[
        // Html() response - XSS if tainted
        SinkDef {
            name: "html_response",
            pattern: SinkKind::FunctionCall("Html"),
            rule_id: "rust/axum-xss",
            severity: Severity::Error,
            description: "Html() response with tainted content",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "html_response_full",
            pattern: SinkKind::FunctionCall("axum::response::Html"),
            rule_id: "rust/axum-xss",
            severity: Severity::Error,
            description: "Html response with tainted content",
            cwe: Some("CWE-79"),
        },
        // Redirect with tainted URL
        SinkDef {
            name: "redirect_to",
            pattern: SinkKind::FunctionCall("Redirect::to"),
            rule_id: "rust/open-redirect",
            severity: Severity::Warning,
            description: "Redirect to tainted URL",
            cwe: Some("CWE-601"),
        },
        SinkDef {
            name: "redirect_permanent",
            pattern: SinkKind::FunctionCall("Redirect::permanent"),
            rule_id: "rust/open-redirect",
            severity: Severity::Warning,
            description: "Permanent redirect to tainted URL",
            cwe: Some("CWE-601"),
        },
        SinkDef {
            name: "redirect_temporary",
            pattern: SinkKind::FunctionCall("Redirect::temporary"),
            rule_id: "rust/open-redirect",
            severity: Severity::Warning,
            description: "Temporary redirect to tainted URL",
            cwe: Some("CWE-601"),
        },
        // Response body
        SinkDef {
            name: "into_response_body",
            pattern: SinkKind::MethodCall(".into_response"),
            rule_id: "rust/axum-xss",
            severity: Severity::Info,
            description: "Custom response - verify content is escaped",
            cwe: Some("CWE-79"),
        },
        // Format in SQL
        SinkDef {
            name: "format_sql",
            pattern: SinkKind::MacroInvocation("format!"),
            rule_id: "rust/sql-injection",
            severity: Severity::Critical,
            description: "format! with SQL and tainted data",
            cwe: Some("CWE-89"),
        },
    ],

    sanitizers: &[
        // Template engines with auto-escaping
        SanitizerDef {
            name: "askama",
            pattern: SanitizerKind::TemplateEngine("askama"),
            sanitizes: "html",
            description: "Askama templates auto-escape HTML",
        },
        SanitizerDef {
            name: "tera",
            pattern: SanitizerKind::TemplateEngine("tera"),
            sanitizes: "html",
            description: "Tera templates auto-escape HTML",
        },
        SanitizerDef {
            name: "minijinja",
            pattern: SanitizerKind::TemplateEngine("minijinja"),
            sanitizes: "html",
            description: "MiniJinja templates auto-escape HTML",
        },
        SanitizerDef {
            name: "maud",
            pattern: SanitizerKind::Macro("html!"),
            sanitizes: "html",
            description: "Maud macro auto-escapes content",
        },
        SanitizerDef {
            name: "maud_doctype",
            pattern: SanitizerKind::Macro("DOCTYPE"),
            sanitizes: "html",
            description: "Maud DOCTYPE macro",
        },
        // HTML sanitization
        SanitizerDef {
            name: "ammonia",
            pattern: SanitizerKind::Function("ammonia::clean"),
            sanitizes: "html",
            description: "Ammonia HTML sanitizer",
        },
        SanitizerDef {
            name: "html_escape",
            pattern: SanitizerKind::Function("html_escape::encode_text"),
            sanitizes: "html",
            description: "HTML entity encoding",
        },
        // URL validation
        SanitizerDef {
            name: "url_parse",
            pattern: SanitizerKind::Function("Url::parse"),
            sanitizes: "url",
            description: "URL parsing validates format",
        },
    ],

    safe_patterns: &[
        // JSON response is safe (no XSS)
        SafePattern {
            name: "json_response",
            pattern: "Json()",
            reason: "JSON serialization escapes content",
        },
        SafePattern {
            name: "axum_json",
            pattern: "axum::Json",
            reason: "JSON response is content-type safe",
        },
        // Parameterized queries
        SafePattern {
            name: "sqlx_query",
            pattern: "sqlx::query!",
            reason: "Compile-time checked parameterized query",
        },
        SafePattern {
            name: "sqlx_query_as",
            pattern: "sqlx::query_as!",
            reason: "Compile-time checked parameterized query",
        },
        SafePattern {
            name: "sqlx_query_scalar",
            pattern: "sqlx::query_scalar!",
            reason: "Compile-time checked parameterized query",
        },
        // Status responses
        SafePattern {
            name: "status_code",
            pattern: "StatusCode::",
            reason: "Status code only response has no body",
        },
    ],

    dangerous_patterns: &[
        // Html with format!
        DangerousPattern {
            name: "html_format",
            pattern: PatternKind::Regex(r"Html\s*\(\s*format!\s*\("),
            rule_id: "rust/axum-xss",
            severity: Severity::Error,
            description: "Html() with format! - use a template engine",
            cwe: Some("CWE-79"),
        },
        // SQL with format!
        DangerousPattern {
            name: "sql_format",
            pattern: PatternKind::Regex(r#"format!\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)"#),
            rule_id: "rust/sql-injection",
            severity: Severity::Error,
            description: "SQL built with format! - use parameterized queries",
            cwe: Some("CWE-89"),
        },
        // Redirect without validation
        DangerousPattern {
            name: "redirect_no_validation",
            pattern: PatternKind::Construct("Redirect::to(user_input) without URL validation"),
            rule_id: "rust/open-redirect",
            severity: Severity::Warning,
            description: "Redirect to user-supplied URL without validation",
            cwe: Some("CWE-601"),
        },
        // Missing authentication
        DangerousPattern {
            name: "public_mutation",
            pattern: PatternKind::Missing("authentication middleware on mutation endpoint"),
            rule_id: "rust/missing-auth",
            severity: Severity::Warning,
            description: "POST/PUT/DELETE endpoint without authentication",
            cwe: Some("CWE-306"),
        },
    ],

    resource_types: &[
        ResourceType {
            name: "Router",
            acquire_pattern: "Router::new()",
            release_pattern: "Consumed by Server::bind().serve()",
            leak_consequence: "Routes not registered",
        },
        ResourceType {
            name: "Extension<Pool>",
            acquire_pattern: ".layer(Extension(pool))",
            release_pattern: "Automatic via Arc",
            leak_consequence: "Connection pool may leak",
        },
        ResourceType {
            name: "WebSocket",
            acquire_pattern: "ws::WebSocket::on_upgrade",
            release_pattern: "Close frame or drop",
            leak_consequence: "WebSocket connection leak",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_axum_profile_detection() {
        assert!(AXUM_PROFILE.is_active("use axum::{Router, routing::get};"));
        assert!(AXUM_PROFILE.is_active("use axum::extract::Query;"));
        assert!(!AXUM_PROFILE.is_active("use actix_web::web;"));
    }

    #[test]
    fn test_axum_extractor_sources() {
        let extractors: Vec<_> = AXUM_PROFILE
            .sources
            .iter()
            .filter(|s| s.name.starts_with("extract_"))
            .collect();
        assert!(
            extractors.len() >= 4,
            "Should have Query, Path, Json, Form extractors"
        );
    }

    #[test]
    fn test_axum_html_sink() {
        let html_sinks: Vec<_> = AXUM_PROFILE
            .sinks
            .iter()
            .filter(|s| s.name.contains("html"))
            .collect();
        assert!(!html_sinks.is_empty(), "Should have Html() sink");
    }

    #[test]
    fn test_axum_template_sanitizers() {
        let templates: Vec<_> = AXUM_PROFILE
            .sanitizers
            .iter()
            .filter(|s| matches!(s.pattern, SanitizerKind::TemplateEngine(_)))
            .collect();
        assert!(
            templates.len() >= 2,
            "Should have multiple template engines"
        );
    }
}
