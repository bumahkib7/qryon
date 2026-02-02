//! Actix-web framework profile
//!
//! Security knowledge for the Actix-web framework, a powerful async web framework
//! for Rust. Covers request handling, extractors, and response building.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Actix-web framework security profile
///
/// Covers:
/// - Request extractors (Query, Path, Json, Form) as taint sources
/// - HttpRequest methods for headers, cookies, etc.
/// - Response builders as potential XSS sinks
/// - Template engine sanitizers
pub static ACTIX_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "actix-web",
    description: "Actix-web framework security patterns",

    detect_imports: &["actix_web", "actix-web", "use actix_web::", "actix_web::"],

    sources: &[
        // Extractors - primary taint sources
        SourceDef {
            name: "web_query",
            pattern: SourceKind::TypeExtractor("web::Query"),
            taint_label: "user_input",
            description: "Query string parameters from URL",
        },
        SourceDef {
            name: "web_query_into_inner",
            pattern: SourceKind::MethodOnType {
                type_pattern: "web::Query",
                method: "into_inner",
            },
            taint_label: "user_input",
            description: "Extracted query parameters",
        },
        SourceDef {
            name: "web_path",
            pattern: SourceKind::TypeExtractor("web::Path"),
            taint_label: "user_input",
            description: "URL path parameters",
        },
        SourceDef {
            name: "web_path_into_inner",
            pattern: SourceKind::MethodOnType {
                type_pattern: "web::Path",
                method: "into_inner",
            },
            taint_label: "user_input",
            description: "Extracted path parameters",
        },
        SourceDef {
            name: "web_json",
            pattern: SourceKind::TypeExtractor("web::Json"),
            taint_label: "user_input",
            description: "JSON request body",
        },
        SourceDef {
            name: "web_json_into_inner",
            pattern: SourceKind::MethodOnType {
                type_pattern: "web::Json",
                method: "into_inner",
            },
            taint_label: "user_input",
            description: "Extracted JSON body",
        },
        SourceDef {
            name: "web_form",
            pattern: SourceKind::TypeExtractor("web::Form"),
            taint_label: "user_input",
            description: "Form data from request body",
        },
        SourceDef {
            name: "web_form_into_inner",
            pattern: SourceKind::MethodOnType {
                type_pattern: "web::Form",
                method: "into_inner",
            },
            taint_label: "user_input",
            description: "Extracted form data",
        },
        SourceDef {
            name: "web_bytes",
            pattern: SourceKind::TypeExtractor("web::Bytes"),
            taint_label: "user_input",
            description: "Raw request body bytes",
        },
        SourceDef {
            name: "web_payload",
            pattern: SourceKind::TypeExtractor("web::Payload"),
            taint_label: "user_input",
            description: "Streaming request body",
        },
        // HttpRequest methods
        SourceDef {
            name: "http_request_headers",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpRequest",
                method: "headers",
            },
            taint_label: "http_headers",
            description: "HTTP request headers",
        },
        SourceDef {
            name: "http_request_cookie",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpRequest",
                method: "cookie",
            },
            taint_label: "cookie",
            description: "Request cookie value",
        },
        SourceDef {
            name: "http_request_query_string",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpRequest",
                method: "query_string",
            },
            taint_label: "user_input",
            description: "Raw query string",
        },
        SourceDef {
            name: "http_request_uri",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpRequest",
                method: "uri",
            },
            taint_label: "url_data",
            description: "Full request URI",
        },
        SourceDef {
            name: "http_request_path",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpRequest",
                method: "path",
            },
            taint_label: "url_data",
            description: "Request path",
        },
        SourceDef {
            name: "http_request_match_info",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpRequest",
                method: "match_info",
            },
            taint_label: "user_input",
            description: "Matched route parameters",
        },
        // Connection info
        SourceDef {
            name: "connection_info_host",
            pattern: SourceKind::MethodOnType {
                type_pattern: "ConnectionInfo",
                method: "host",
            },
            taint_label: "http_headers",
            description: "Host header (can be spoofed)",
        },
        SourceDef {
            name: "connection_info_realip",
            pattern: SourceKind::MethodOnType {
                type_pattern: "ConnectionInfo",
                method: "realip_remote_addr",
            },
            taint_label: "http_headers",
            description: "X-Forwarded-For IP (can be spoofed)",
        },
    ],

    sinks: &[
        // Response body with tainted content (XSS)
        SinkDef {
            name: "http_response_body",
            pattern: SinkKind::ResponseBody("HttpResponse::body"),
            rule_id: "rust/actix-xss",
            severity: Severity::Error,
            description: "Tainted data in response body without escaping",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "http_response_ok_body",
            pattern: SinkKind::MethodCall(".body"),
            rule_id: "rust/actix-xss",
            severity: Severity::Warning,
            description: "Response body may contain tainted data",
            cwe: Some("CWE-79"),
        },
        // Format in SQL context
        SinkDef {
            name: "format_sql",
            pattern: SinkKind::MacroInvocation("format!"),
            rule_id: "rust/sql-injection",
            severity: Severity::Critical,
            description: "format! with SQL query and tainted data",
            cwe: Some("CWE-89"),
        },
        // Command execution
        SinkDef {
            name: "command_arg_tainted",
            pattern: SinkKind::MethodCall("Command::new().arg"),
            rule_id: "rust/command-injection",
            severity: Severity::Critical,
            description: "Command with tainted argument",
            cwe: Some("CWE-78"),
        },
        // Redirect with tainted URL
        SinkDef {
            name: "redirect_tainted",
            pattern: SinkKind::FunctionCall("HttpResponse::Found"),
            rule_id: "rust/open-redirect",
            severity: Severity::Warning,
            description: "Redirect to tainted URL",
            cwe: Some("CWE-601"),
        },
        SinkDef {
            name: "redirect_see_other",
            pattern: SinkKind::FunctionCall("HttpResponse::SeeOther"),
            rule_id: "rust/open-redirect",
            severity: Severity::Warning,
            description: "Redirect to tainted URL",
            cwe: Some("CWE-601"),
        },
    ],

    sanitizers: &[
        // Template engines with auto-escaping
        SanitizerDef {
            name: "askama",
            pattern: SanitizerKind::TemplateEngine("askama"),
            sanitizes: "html",
            description: "Askama templates auto-escape by default",
        },
        SanitizerDef {
            name: "tera",
            pattern: SanitizerKind::TemplateEngine("tera"),
            sanitizes: "html",
            description: "Tera templates auto-escape by default",
        },
        SanitizerDef {
            name: "maud",
            pattern: SanitizerKind::Macro("html!"),
            sanitizes: "html",
            description: "Maud macro auto-escapes content",
        },
        // HTML sanitization libraries
        SanitizerDef {
            name: "ammonia_clean",
            pattern: SanitizerKind::Function("ammonia::clean"),
            sanitizes: "html",
            description: "Ammonia HTML sanitizer - removes dangerous elements",
        },
        SanitizerDef {
            name: "ammonia_builder",
            pattern: SanitizerKind::MethodCall("ammonia::Builder::clean"),
            sanitizes: "html",
            description: "Ammonia builder with custom rules",
        },
        SanitizerDef {
            name: "html_escape_encode",
            pattern: SanitizerKind::Function("html_escape::encode_text"),
            sanitizes: "html",
            description: "HTML entity encoding",
        },
        SanitizerDef {
            name: "html_escape_encode_safe",
            pattern: SanitizerKind::Function("html_escape::encode_safe"),
            sanitizes: "html",
            description: "HTML entity encoding (safe)",
        },
        SanitizerDef {
            name: "html_escape_encode_quoted",
            pattern: SanitizerKind::Function("html_escape::encode_quoted_attribute"),
            sanitizes: "html",
            description: "HTML attribute encoding",
        },
        // URL encoding
        SanitizerDef {
            name: "urlencoding_encode",
            pattern: SanitizerKind::Function("urlencoding::encode"),
            sanitizes: "url",
            description: "URL encoding",
        },
    ],

    safe_patterns: &[
        // Parameterized queries
        SafePattern {
            name: "sqlx_query_macro",
            pattern: "sqlx::query!",
            reason: "Compile-time checked SQL query with parameterized values",
        },
        SafePattern {
            name: "sqlx_query_as_macro",
            pattern: "sqlx::query_as!",
            reason: "Compile-time checked SQL query with type mapping",
        },
        SafePattern {
            name: "diesel_query_builder",
            pattern: "diesel::QueryDsl",
            reason: "Diesel query builder uses parameterized queries",
        },
        SafePattern {
            name: "sea_orm_query",
            pattern: "sea_orm::QueryTrait",
            reason: "Sea-ORM uses parameterized queries",
        },
        // Static responses
        SafePattern {
            name: "http_response_ok",
            pattern: "HttpResponse::Ok().finish()",
            reason: "Empty response body is safe",
        },
        SafePattern {
            name: "json_response",
            pattern: "HttpResponse::Ok().json()",
            reason: "JSON serialization escapes special characters",
        },
    ],

    dangerous_patterns: &[
        // SQL string interpolation
        DangerousPattern {
            name: "format_sql_string",
            pattern: PatternKind::Regex(r#"format!\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE)"#),
            rule_id: "rust/sql-injection",
            severity: Severity::Error,
            description: "SQL query built with format! - use parameterized queries",
            cwe: Some("CWE-89"),
        },
        // Reflected content in response
        DangerousPattern {
            name: "reflected_param",
            pattern: PatternKind::Construct("HttpResponse body contains request param directly"),
            rule_id: "rust/actix-reflected-xss",
            severity: Severity::Error,
            description: "Request parameter reflected in response without escaping",
            cwe: Some("CWE-79"),
        },
        // Missing CSRF protection
        DangerousPattern {
            name: "form_no_csrf",
            pattern: PatternKind::Missing("CSRF token validation for POST form"),
            rule_id: "rust/actix-csrf",
            severity: Severity::Warning,
            description: "Form endpoint without CSRF protection",
            cwe: Some("CWE-352"),
        },
        // Session fixation
        DangerousPattern {
            name: "session_no_regenerate",
            pattern: PatternKind::Missing("session ID regeneration after login"),
            rule_id: "rust/session-fixation",
            severity: Severity::Warning,
            description: "Session ID not regenerated after authentication",
            cwe: Some("CWE-384"),
        },
    ],

    resource_types: &[
        ResourceType {
            name: "HttpServer",
            acquire_pattern: "HttpServer::new",
            release_pattern: ".shutdown_timeout() or graceful shutdown",
            leak_consequence: "Port remains bound, connections may hang",
        },
        ResourceType {
            name: "Data<Pool>",
            acquire_pattern: "web::Data::new(pool)",
            release_pattern: "Automatic via App lifetime",
            leak_consequence: "Database connections may leak",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actix_profile_detection() {
        assert!(ACTIX_PROFILE.is_active("use actix_web::{web, App};"));
        assert!(ACTIX_PROFILE.is_active("use actix_web::HttpServer;"));
        assert!(!ACTIX_PROFILE.is_active("use rocket::get;"));
    }

    #[test]
    fn test_actix_extractor_sources() {
        let extractors: Vec<_> = ACTIX_PROFILE
            .sources
            .iter()
            .filter(|s| s.name.starts_with("web_"))
            .collect();
        assert!(
            extractors.len() >= 4,
            "Should have Query, Path, Json, Form extractors"
        );
    }

    #[test]
    fn test_actix_sanitizers() {
        let sanitizers: Vec<_> = ACTIX_PROFILE
            .sanitizers
            .iter()
            .filter(|s| s.sanitizes == "html")
            .collect();
        assert!(!sanitizers.is_empty(), "Should have HTML sanitizers");
    }

    #[test]
    fn test_actix_safe_patterns() {
        assert!(
            ACTIX_PROFILE
                .safe_patterns
                .iter()
                .any(|p| p.name.contains("sqlx")),
            "Should have sqlx as safe pattern"
        );
    }
}
