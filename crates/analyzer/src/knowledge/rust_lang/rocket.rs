//! Rocket framework profile
//!
//! Security knowledge for the Rocket web framework, known for its
//! ergonomic API and type-safe request handling.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Rocket framework security profile
///
/// Covers:
/// - Path parameters via #[get("/<param>")]
/// - Form<T> and Query<T> extractors
/// - CookieJar access
/// - Data<T> for request body
/// - Request guards and headers
pub static ROCKET_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "rocket",
    description: "Rocket framework security patterns",

    detect_imports: &[
        "rocket",
        "use rocket::",
        "rocket::",
        "#[rocket::main]",
        "#[launch]",
    ],

    sources: &[
        // Path parameters (from route definition)
        SourceDef {
            name: "path_param",
            pattern: SourceKind::TypeExtractor("path_param"),
            taint_label: "user_input",
            description: "URL path parameter from route",
        },
        // Form data
        SourceDef {
            name: "form",
            pattern: SourceKind::TypeExtractor("Form"),
            taint_label: "user_input",
            description: "Form data from request body",
        },
        SourceDef {
            name: "form_full_path",
            pattern: SourceKind::TypeExtractor("rocket::form::Form"),
            taint_label: "user_input",
            description: "Form data from request body",
        },
        SourceDef {
            name: "form_lenient",
            pattern: SourceKind::TypeExtractor("LenientForm"),
            taint_label: "user_input",
            description: "Lenient form data (ignores extra fields)",
        },
        SourceDef {
            name: "form_field",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Form",
                method: "into_inner",
            },
            taint_label: "user_input",
            description: "Extracted form field value",
        },
        // Query string
        SourceDef {
            name: "query",
            pattern: SourceKind::TypeExtractor("Query"),
            taint_label: "user_input",
            description: "Query string parameter",
        },
        SourceDef {
            name: "query_full_path",
            pattern: SourceKind::TypeExtractor("rocket::request::Query"),
            taint_label: "user_input",
            description: "Query string parameters",
        },
        // Cookies
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
            description: "Get specific cookie",
        },
        SourceDef {
            name: "cookie_get_private",
            pattern: SourceKind::MethodOnType {
                type_pattern: "CookieJar",
                method: "get_private",
            },
            taint_label: "cookie",
            description: "Get encrypted cookie (still user-controlled)",
        },
        SourceDef {
            name: "cookie_value",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Cookie",
                method: "value",
            },
            taint_label: "cookie",
            description: "Cookie value",
        },
        // Request body
        SourceDef {
            name: "data",
            pattern: SourceKind::TypeExtractor("Data"),
            taint_label: "user_input",
            description: "Raw request body stream",
        },
        SourceDef {
            name: "data_open",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Data",
                method: "open",
            },
            taint_label: "user_input",
            description: "Open data stream for reading",
        },
        // JSON body
        SourceDef {
            name: "json",
            pattern: SourceKind::TypeExtractor("Json"),
            taint_label: "user_input",
            description: "JSON request body",
        },
        SourceDef {
            name: "json_full_path",
            pattern: SourceKind::TypeExtractor("rocket::serde::json::Json"),
            taint_label: "user_input",
            description: "JSON request body",
        },
        SourceDef {
            name: "json_into_inner",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Json",
                method: "into_inner",
            },
            taint_label: "user_input",
            description: "Extracted JSON value",
        },
        // Headers
        SourceDef {
            name: "request_headers",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Request",
                method: "headers",
            },
            taint_label: "http_headers",
            description: "Request headers",
        },
        SourceDef {
            name: "header_one",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HeaderMap",
                method: "get_one",
            },
            taint_label: "http_headers",
            description: "Get single header value",
        },
        SourceDef {
            name: "content_type",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Request",
                method: "content_type",
            },
            taint_label: "http_headers",
            description: "Content-Type header",
        },
        // URI/URL
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
            name: "path_param_uri",
            pattern: SourceKind::TypeExtractor("rocket::http::uri::Path"),
            taint_label: "user_input",
            description: "URL path parameter",
        },
        // Client IP (can be spoofed via X-Forwarded-For)
        SourceDef {
            name: "client_ip",
            pattern: SourceKind::MethodOnType {
                type_pattern: "Request",
                method: "client_ip",
            },
            taint_label: "http_headers",
            description: "Client IP (may be from X-Forwarded-For)",
        },
        // File uploads
        SourceDef {
            name: "temp_file",
            pattern: SourceKind::TypeExtractor("TempFile"),
            taint_label: "user_input",
            description: "Uploaded file",
        },
        SourceDef {
            name: "file_name",
            pattern: SourceKind::MethodOnType {
                type_pattern: "TempFile",
                method: "name",
            },
            taint_label: "user_input",
            description: "Uploaded file name (user-controlled)",
        },
    ],

    sinks: &[
        // HTML content response
        SinkDef {
            name: "content_html",
            pattern: SinkKind::FunctionCall("content::Html"),
            rule_id: "rust/rocket-xss",
            severity: Severity::Error,
            description: "HTML response with tainted content",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "content_raw_html",
            pattern: SinkKind::FunctionCall("content::RawHtml"),
            rule_id: "rust/rocket-xss",
            severity: Severity::Error,
            description: "Raw HTML response (no escaping)",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "response_content",
            pattern: SinkKind::MethodCall("content"),
            rule_id: "rust/rocket-xss",
            severity: Severity::Warning,
            description: "Response content may contain tainted data",
            cwe: Some("CWE-79"),
        },
        // Redirect
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
        SinkDef {
            name: "redirect_found",
            pattern: SinkKind::FunctionCall("Redirect::found"),
            rule_id: "rust/open-redirect",
            severity: Severity::Warning,
            description: "302 redirect to tainted URL",
            cwe: Some("CWE-601"),
        },
        // NamedFile with tainted path
        SinkDef {
            name: "named_file_open",
            pattern: SinkKind::FunctionCall("NamedFile::open"),
            rule_id: "rust/path-traversal",
            severity: Severity::Error,
            description: "File access with tainted path",
            cwe: Some("CWE-22"),
        },
        // SQL injection
        SinkDef {
            name: "format_sql",
            pattern: SinkKind::MacroInvocation("format!"),
            rule_id: "rust/sql-injection",
            severity: Severity::Critical,
            description: "SQL query with tainted interpolation",
            cwe: Some("CWE-89"),
        },
        // Command injection
        SinkDef {
            name: "command_tainted",
            pattern: SinkKind::FunctionCall("Command::new"),
            rule_id: "rust/command-injection",
            severity: Severity::Critical,
            description: "Command execution with tainted input",
            cwe: Some("CWE-78"),
        },
    ],

    sanitizers: &[
        // Rocket's built-in template support
        SanitizerDef {
            name: "rocket_templates",
            pattern: SanitizerKind::TemplateEngine("rocket_dyn_templates"),
            sanitizes: "html",
            description: "Rocket dynamic templates (Tera/Handlebars) with auto-escaping",
        },
        // Tera (commonly used with Rocket)
        SanitizerDef {
            name: "tera",
            pattern: SanitizerKind::TemplateEngine("tera"),
            sanitizes: "html",
            description: "Tera template engine auto-escapes",
        },
        // Handlebars
        SanitizerDef {
            name: "handlebars",
            pattern: SanitizerKind::TemplateEngine("handlebars"),
            sanitizes: "html",
            description: "Handlebars template engine auto-escapes",
        },
        // Askama
        SanitizerDef {
            name: "askama",
            pattern: SanitizerKind::TemplateEngine("askama"),
            sanitizes: "html",
            description: "Askama templates auto-escape",
        },
        // Maud
        SanitizerDef {
            name: "maud",
            pattern: SanitizerKind::Macro("html!"),
            sanitizes: "html",
            description: "Maud macro auto-escapes",
        },
        // HTML escaping
        SanitizerDef {
            name: "html_escape",
            pattern: SanitizerKind::Function("html_escape::encode_text"),
            sanitizes: "html",
            description: "Manual HTML escaping",
        },
        SanitizerDef {
            name: "ammonia",
            pattern: SanitizerKind::Function("ammonia::clean"),
            sanitizes: "html",
            description: "Ammonia HTML sanitizer",
        },
        // URL encoding
        SanitizerDef {
            name: "rocket_uri",
            pattern: SanitizerKind::Macro("uri!"),
            sanitizes: "url",
            description: "Rocket uri! macro validates and encodes",
        },
    ],

    safe_patterns: &[
        // JSON response
        SafePattern {
            name: "json_response",
            pattern: "Json()",
            reason: "JSON serialization is safe from XSS",
        },
        SafePattern {
            name: "json_response_full",
            pattern: "rocket::serde::json::Json",
            reason: "JSON serialization escapes special characters",
        },
        // Typed routes
        SafePattern {
            name: "typed_uri",
            pattern: "uri!(route_name: param)",
            reason: "Type-safe URI generation",
        },
        // Static file serving from known directory
        SafePattern {
            name: "static_files",
            pattern: "FileServer::from(\"static\")",
            reason: "Serves from predefined directory only",
        },
        // Parameterized queries
        SafePattern {
            name: "sqlx_query",
            pattern: "sqlx::query!",
            reason: "Compile-time checked parameterized query",
        },
        SafePattern {
            name: "diesel_dsl",
            pattern: "diesel::dsl",
            reason: "Diesel query builder uses parameterized queries",
        },
        // Form validation
        SafePattern {
            name: "form_validation",
            pattern: "#[field(validate)]",
            reason: "Rocket form validation attribute",
        },
    ],

    dangerous_patterns: &[
        // HTML content with format!
        DangerousPattern {
            name: "html_format",
            pattern: PatternKind::Regex(r"content::Html\s*\(\s*format!\s*\("),
            rule_id: "rust/rocket-xss",
            severity: Severity::Error,
            description: "content::Html with format! - use template engine",
            cwe: Some("CWE-79"),
        },
        DangerousPattern {
            name: "raw_html_response",
            pattern: PatternKind::MethodCall("RawHtml"),
            rule_id: "rust/rocket-raw-html",
            severity: Severity::Warning,
            description: "RawHtml bypasses escaping - ensure content is trusted",
            cwe: Some("CWE-79"),
        },
        DangerousPattern {
            name: "raw_html_format",
            pattern: PatternKind::Regex(r"content::RawHtml\s*\(\s*format!\s*\("),
            rule_id: "rust/rocket-xss",
            severity: Severity::Critical,
            description: "RawHtml with format! - definitely unsafe",
            cwe: Some("CWE-79"),
        },
        // SQL with format!
        DangerousPattern {
            name: "sql_format",
            pattern: PatternKind::Regex(r#"format!\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)"#),
            rule_id: "rust/sql-injection",
            severity: Severity::Error,
            description: "SQL built with format!",
            cwe: Some("CWE-89"),
        },
        // NamedFile with user input
        DangerousPattern {
            name: "named_file_user_path",
            pattern: PatternKind::Construct("NamedFile::open(user_provided_path)"),
            rule_id: "rust/path-traversal",
            severity: Severity::Error,
            description: "File access with user-controlled path",
            cwe: Some("CWE-22"),
        },
        // Redirect without validation
        DangerousPattern {
            name: "open_redirect",
            pattern: PatternKind::Construct("Redirect::to(user_input) without validation"),
            rule_id: "rust/open-redirect",
            severity: Severity::Warning,
            description: "Redirect to user-supplied URL",
            cwe: Some("CWE-601"),
        },
        // Missing CSRF on state-changing endpoints
        DangerousPattern {
            name: "post_no_csrf",
            pattern: PatternKind::Missing("CSRF protection on POST endpoint"),
            rule_id: "rust/rocket-csrf",
            severity: Severity::Warning,
            description: "POST endpoint without CSRF token validation",
            cwe: Some("CWE-352"),
        },
        // Using deprecated LenientForm
        DangerousPattern {
            name: "lenient_form",
            pattern: PatternKind::Construct("LenientForm"),
            rule_id: "rust/rocket-lenient-form",
            severity: Severity::Info,
            description: "LenientForm ignores validation - consider strict Form",
            cwe: None,
        },
    ],

    resource_types: &[
        ResourceType {
            name: "Rocket",
            acquire_pattern: "rocket::build()",
            release_pattern: ".launch() consumes or graceful shutdown",
            leak_consequence: "Server may not shut down cleanly",
        },
        ResourceType {
            name: "DbConn",
            acquire_pattern: "#[database] pool connection",
            release_pattern: "Drop (automatic)",
            leak_consequence: "Database connection leak",
        },
        ResourceType {
            name: "TempFile",
            acquire_pattern: "TempFile extractor",
            release_pattern: "persist() or Drop (deleted)",
            leak_consequence: "Temporary file remains on disk",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rocket_profile_detection() {
        assert!(ROCKET_PROFILE.is_active("use rocket::{get, routes};"));
        assert!(ROCKET_PROFILE.is_active("#[rocket::main]"));
        assert!(ROCKET_PROFILE.is_active("#[launch]"));
        assert!(!ROCKET_PROFILE.is_active("use axum::Router;"));
        assert!(!ROCKET_PROFILE.is_active("use actix_web::App;"));
    }

    #[test]
    fn test_rocket_form_sources() {
        let form_sources: Vec<_> = ROCKET_PROFILE
            .sources
            .iter()
            .filter(|s| s.name.contains("form"))
            .collect();
        assert!(!form_sources.is_empty(), "Should have form sources");
    }

    #[test]
    fn test_rocket_cookie_sources() {
        let cookie_sources: Vec<_> = ROCKET_PROFILE
            .sources
            .iter()
            .filter(|s| s.taint_label == "cookie")
            .collect();
        assert!(cookie_sources.len() >= 2, "Should have cookie sources");
    }

    #[test]
    fn test_rocket_html_sinks() {
        let html_sinks: Vec<_> = ROCKET_PROFILE
            .sinks
            .iter()
            .filter(|s| s.name.contains("html") || s.name.contains("content"))
            .collect();
        assert!(html_sinks.len() >= 2, "Should have Html and RawHtml sinks");
    }

    #[test]
    fn test_rocket_template_sanitizers() {
        let templates: Vec<_> = ROCKET_PROFILE
            .sanitizers
            .iter()
            .filter(|s| s.sanitizes == "html")
            .collect();
        assert!(templates.len() >= 3, "Should have multiple HTML sanitizers");
    }

    #[test]
    fn test_rocket_safe_patterns() {
        assert!(
            ROCKET_PROFILE
                .safe_patterns
                .iter()
                .any(|p| p.name.contains("json")),
            "Should have JSON response as safe"
        );
        assert!(
            ROCKET_PROFILE
                .safe_patterns
                .iter()
                .any(|p| p.name == "typed_uri"),
            "Should have typed URI as safe"
        );
    }
}
