//! Gin web framework profile
//!
//! Security knowledge for the Gin web framework - one of the most popular
//! Go web frameworks with high performance and a Martini-like API.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Gin web framework profile
pub static GIN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "gin",
    description: "Gin - High-performance Go web framework with Martini-like API",
    detect_imports: &["github.com/gin-gonic/gin", "gin-gonic/gin"],

    sources: &[
        // Query parameters
        SourceDef {
            name: "query",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "Query",
            },
            taint_label: "user_input",
            description: "Query parameter from URL - user controllable",
        },
        SourceDef {
            name: "default_query",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "DefaultQuery",
            },
            taint_label: "user_input",
            description: "Query parameter with default - user controllable",
        },
        SourceDef {
            name: "query_array",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "QueryArray",
            },
            taint_label: "user_input",
            description: "Query parameter array - user controllable",
        },
        SourceDef {
            name: "query_map",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "QueryMap",
            },
            taint_label: "user_input",
            description: "Query parameter map - user controllable",
        },
        // Path parameters
        SourceDef {
            name: "param",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "Param",
            },
            taint_label: "user_input",
            description: "URL path parameter - user controllable",
        },
        // Form data
        SourceDef {
            name: "post_form",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "PostForm",
            },
            taint_label: "user_input",
            description: "POST form field - user controllable",
        },
        SourceDef {
            name: "default_post_form",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "DefaultPostForm",
            },
            taint_label: "user_input",
            description: "POST form field with default - user controllable",
        },
        SourceDef {
            name: "post_form_array",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "PostFormArray",
            },
            taint_label: "user_input",
            description: "POST form array - user controllable",
        },
        SourceDef {
            name: "post_form_map",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "PostFormMap",
            },
            taint_label: "user_input",
            description: "POST form map - user controllable",
        },
        // Headers
        SourceDef {
            name: "get_header",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "GetHeader",
            },
            taint_label: "user_input",
            description: "HTTP header value - can be user controllable",
        },
        // Cookies
        SourceDef {
            name: "cookie",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "Cookie",
            },
            taint_label: "user_input",
            description: "Cookie value - user controllable",
        },
        // Request body binding
        SourceDef {
            name: "bind_json",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "BindJSON",
            },
            taint_label: "user_input",
            description: "JSON body binding - user controllable",
        },
        SourceDef {
            name: "should_bind_json",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "ShouldBindJSON",
            },
            taint_label: "user_input",
            description: "JSON body binding - user controllable",
        },
        SourceDef {
            name: "bind",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "Bind",
            },
            taint_label: "user_input",
            description: "Auto body binding - user controllable",
        },
        SourceDef {
            name: "should_bind",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "ShouldBind",
            },
            taint_label: "user_input",
            description: "Auto body binding - user controllable",
        },
        SourceDef {
            name: "bind_uri",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "BindUri",
            },
            taint_label: "user_input",
            description: "URI binding - user controllable",
        },
        // Raw body
        SourceDef {
            name: "get_raw_data",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "GetRawData",
            },
            taint_label: "user_input",
            description: "Raw request body - user controllable",
        },
        // File uploads
        SourceDef {
            name: "form_file",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "FormFile",
            },
            taint_label: "user_file",
            description: "Uploaded file - user controllable content and filename",
        },
        SourceDef {
            name: "multipart_form",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*gin.Context",
                method: "MultipartForm",
            },
            taint_label: "user_input",
            description: "Multipart form data - user controllable",
        },
    ],

    sinks: &[
        // XSS sinks
        SinkDef {
            name: "html_tainted",
            pattern: SinkKind::MethodCall("HTML"),
            rule_id: "go/gin-xss-html",
            severity: Severity::Warning,
            description: "c.HTML with tainted data in template context may cause XSS",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "string_tainted",
            pattern: SinkKind::MethodCall("String"),
            rule_id: "go/gin-xss-string",
            severity: Severity::Warning,
            description: "c.String with tainted format string may cause injection",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "data_html",
            pattern: SinkKind::MethodCall("Data"),
            rule_id: "go/gin-xss-data",
            severity: Severity::Warning,
            description: "c.Data with HTML content type and tainted data may cause XSS",
            cwe: Some("CWE-79"),
        },
        // Open redirect
        SinkDef {
            name: "redirect",
            pattern: SinkKind::MethodCall("Redirect"),
            rule_id: "go/gin-open-redirect",
            severity: Severity::Warning,
            description: "c.Redirect with user-controlled URL may cause open redirect",
            cwe: Some("CWE-601"),
        },
        // Header injection
        SinkDef {
            name: "header_set",
            pattern: SinkKind::MethodCall("Header"),
            rule_id: "go/gin-header-injection",
            severity: Severity::Warning,
            description: "c.Header with user input may cause header injection",
            cwe: Some("CWE-113"),
        },
        // File serving with path traversal risk
        SinkDef {
            name: "file",
            pattern: SinkKind::MethodCall("File"),
            rule_id: "go/gin-path-traversal",
            severity: Severity::Warning,
            description: "c.File with user-controlled path may cause path traversal",
            cwe: Some("CWE-22"),
        },
        SinkDef {
            name: "file_attachment",
            pattern: SinkKind::MethodCall("FileAttachment"),
            rule_id: "go/gin-path-traversal",
            severity: Severity::Warning,
            description: "c.FileAttachment with user-controlled path may cause path traversal",
            cwe: Some("CWE-22"),
        },
    ],

    sanitizers: &[
        // Gin's HTML template auto-escaping (when using html/template)
        SanitizerDef {
            name: "gin_html_template",
            pattern: SanitizerKind::TemplateEngine("gin.LoadHTMLGlob"),
            sanitizes: "html",
            description: "Gin HTML templates use html/template which auto-escapes",
        },
        SanitizerDef {
            name: "gin_html_files",
            pattern: SanitizerKind::TemplateEngine("gin.LoadHTMLFiles"),
            sanitizes: "html",
            description: "Gin HTML templates use html/template which auto-escapes",
        },
        // Bluemonday HTML sanitizer (commonly used with Gin)
        SanitizerDef {
            name: "bluemonday_strict",
            pattern: SanitizerKind::Function("bluemonday.StrictPolicy"),
            sanitizes: "html",
            description: "Bluemonday strict policy strips all HTML tags",
        },
        SanitizerDef {
            name: "bluemonday_ugc",
            pattern: SanitizerKind::Function("bluemonday.UGCPolicy"),
            sanitizes: "html",
            description: "Bluemonday UGC policy allows safe HTML subset",
        },
        SanitizerDef {
            name: "bluemonday_sanitize",
            pattern: SanitizerKind::MethodCall("Sanitize"),
            sanitizes: "html",
            description: "Bluemonday Sanitize method cleans HTML",
        },
        // Validator binding (provides input validation)
        SanitizerDef {
            name: "binding_validation",
            pattern: SanitizerKind::Function("binding.Validator"),
            sanitizes: "validated",
            description: "Gin binding validation constrains input format",
        },
    ],

    safe_patterns: &[
        SafePattern {
            name: "gin_json_response",
            pattern: "c.JSON",
            reason: "c.JSON auto-serializes to JSON, preventing XSS",
        },
        SafePattern {
            name: "gin_xml_response",
            pattern: "c.XML",
            reason: "c.XML auto-serializes to XML with proper encoding",
        },
        SafePattern {
            name: "gin_yaml_response",
            pattern: "c.YAML",
            reason: "c.YAML auto-serializes to YAML",
        },
        SafePattern {
            name: "gin_protobuf_response",
            pattern: "c.ProtoBuf",
            reason: "c.ProtoBuf uses binary protocol",
        },
        SafePattern {
            name: "gin_secure_json",
            pattern: "c.SecureJSON",
            reason: "c.SecureJSON adds prefix to prevent JSON hijacking",
        },
        SafePattern {
            name: "static_redirect",
            pattern: "c.Redirect(http.StatusFound, \"/",
            reason: "Redirect to hardcoded path starting with / is safe",
        },
    ],

    dangerous_patterns: &[
        // Format string in c.String
        DangerousPattern {
            name: "string_format_injection",
            pattern: PatternKind::Regex(r#"c\.String\([^,]+,\s*[^"']"#),
            rule_id: "go/gin-format-string",
            severity: Severity::Warning,
            description: "c.String with variable format string may cause issues",
            cwe: Some("CWE-134"),
        },
        // Raw HTML in template
        DangerousPattern {
            name: "raw_html_template",
            pattern: PatternKind::Construct("template.HTML"),
            rule_id: "go/gin-raw-html",
            severity: Severity::Error,
            description: "template.HTML in Gin context bypasses auto-escaping",
            cwe: Some("CWE-79"),
        },
        // Missing CSRF protection
        DangerousPattern {
            name: "post_without_csrf",
            pattern: PatternKind::Missing("csrf middleware"),
            rule_id: "go/gin-missing-csrf",
            severity: Severity::Warning,
            description: "POST endpoints should have CSRF protection",
            cwe: Some("CWE-352"),
        },
        // Debug mode in production
        DangerousPattern {
            name: "debug_mode",
            pattern: PatternKind::Construct("gin.DebugMode"),
            rule_id: "go/gin-debug-mode",
            severity: Severity::Info,
            description: "Ensure gin.DebugMode is not used in production",
            cwe: None,
        },
        // Trusting proxy headers without middleware
        DangerousPattern {
            name: "trust_all_proxies",
            pattern: PatternKind::Construct("TrustedProxies"),
            rule_id: "go/gin-proxy-trust",
            severity: Severity::Warning,
            description: "Review TrustedProxies configuration for IP spoofing",
            cwe: Some("CWE-290"),
        },
    ],

    resource_types: &[
        // Gin context is managed by the framework, but file uploads need cleanup
        ResourceType {
            name: "multipart.FileHeader",
            acquire_pattern: "c.FormFile|c.MultipartForm",
            release_pattern: "file.Close()",
            leak_consequence: "Uploaded file handle leak",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gin_detection() {
        let content = r#"
            package main
            import "github.com/gin-gonic/gin"
        "#;
        assert!(GIN_PROFILE.is_active(content));
    }

    #[test]
    fn test_gin_detection_partial() {
        let content = r#"
            package main
            import "gin-gonic/gin"
        "#;
        assert!(GIN_PROFILE.is_active(content));
    }

    #[test]
    fn test_has_query_source() {
        assert!(GIN_PROFILE.sources.iter().any(|s| s.name == "query"));
    }

    #[test]
    fn test_has_param_source() {
        assert!(GIN_PROFILE.sources.iter().any(|s| s.name == "param"));
    }

    #[test]
    fn test_has_xss_sinks() {
        assert!(GIN_PROFILE.sinks.iter().any(|s| s.name == "html_tainted"));
    }

    #[test]
    fn test_has_safe_json() {
        assert!(
            GIN_PROFILE
                .safe_patterns
                .iter()
                .any(|s| s.name == "gin_json_response")
        );
    }
}
