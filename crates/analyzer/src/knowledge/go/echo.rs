//! Echo web framework profile
//!
//! Security knowledge for the Echo web framework - a high-performance,
//! minimalist Go web framework with extensive middleware support.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Echo web framework profile
pub static ECHO_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "echo",
    description: "Echo - High-performance, minimalist Go web framework",
    detect_imports: &[
        "github.com/labstack/echo",
        "labstack/echo",
        "github.com/labstack/echo/v4",
        "labstack/echo/v4",
    ],

    sources: &[
        // Query parameters
        SourceDef {
            name: "query_param",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "QueryParam",
            },
            taint_label: "user_input",
            description: "Query parameter from URL - user controllable",
        },
        SourceDef {
            name: "query_params",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "QueryParams",
            },
            taint_label: "user_input",
            description: "All query parameters - user controllable",
        },
        SourceDef {
            name: "query_string",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "QueryString",
            },
            taint_label: "user_input",
            description: "Raw query string - user controllable",
        },
        // Path parameters
        SourceDef {
            name: "param",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "Param",
            },
            taint_label: "user_input",
            description: "URL path parameter - user controllable",
        },
        SourceDef {
            name: "param_names",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "ParamNames",
            },
            taint_label: "user_input",
            description: "URL path parameter names",
        },
        SourceDef {
            name: "param_values",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "ParamValues",
            },
            taint_label: "user_input",
            description: "URL path parameter values - user controllable",
        },
        // Form data
        SourceDef {
            name: "form_value",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "FormValue",
            },
            taint_label: "user_input",
            description: "Form field value - user controllable",
        },
        SourceDef {
            name: "form_params",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "FormParams",
            },
            taint_label: "user_input",
            description: "All form parameters - user controllable",
        },
        SourceDef {
            name: "multipart_form",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "MultipartForm",
            },
            taint_label: "user_input",
            description: "Multipart form data - user controllable",
        },
        // Headers
        SourceDef {
            name: "request_header",
            pattern: SourceKind::MemberAccess("c.Request().Header"),
            taint_label: "user_input",
            description: "HTTP header value - can be user controllable",
        },
        // Cookies
        SourceDef {
            name: "cookie",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "Cookie",
            },
            taint_label: "user_input",
            description: "Cookie value - user controllable",
        },
        SourceDef {
            name: "cookies",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "Cookies",
            },
            taint_label: "user_input",
            description: "All cookies - user controllable",
        },
        // Request body binding
        SourceDef {
            name: "bind",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "Bind",
            },
            taint_label: "user_input",
            description: "Auto body binding - user controllable",
        },
        // File uploads
        SourceDef {
            name: "form_file",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "FormFile",
            },
            taint_label: "user_file",
            description: "Uploaded file - user controllable content and filename",
        },
        // Path and scheme
        SourceDef {
            name: "path",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "Path",
            },
            taint_label: "user_input",
            description: "Request path - user controllable",
        },
        // Real IP (through proxy)
        SourceDef {
            name: "real_ip",
            pattern: SourceKind::MethodOnType {
                type_pattern: "echo.Context",
                method: "RealIP",
            },
            taint_label: "untrusted_metadata",
            description: "Real IP - can be spoofed via proxy headers",
        },
    ],

    sinks: &[
        // XSS sinks
        SinkDef {
            name: "html",
            pattern: SinkKind::MethodCall("HTML"),
            rule_id: "go/echo-xss-html",
            severity: Severity::Warning,
            description: "c.HTML with tainted template data may cause XSS",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "string",
            pattern: SinkKind::MethodCall("String"),
            rule_id: "go/echo-xss-string",
            severity: Severity::Warning,
            description: "c.String with tainted content may cause XSS",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "html_blob",
            pattern: SinkKind::MethodCall("HTMLBlob"),
            rule_id: "go/echo-xss-htmlblob",
            severity: Severity::Warning,
            description: "c.HTMLBlob with tainted content may cause XSS",
            cwe: Some("CWE-79"),
        },
        // Open redirect
        SinkDef {
            name: "redirect",
            pattern: SinkKind::MethodCall("Redirect"),
            rule_id: "go/echo-open-redirect",
            severity: Severity::Warning,
            description: "c.Redirect with user-controlled URL may cause open redirect",
            cwe: Some("CWE-601"),
        },
        // File operations with path traversal risk
        SinkDef {
            name: "file",
            pattern: SinkKind::MethodCall("File"),
            rule_id: "go/echo-path-traversal",
            severity: Severity::Warning,
            description: "c.File with user-controlled path may cause path traversal",
            cwe: Some("CWE-22"),
        },
        SinkDef {
            name: "attachment",
            pattern: SinkKind::MethodCall("Attachment"),
            rule_id: "go/echo-path-traversal",
            severity: Severity::Warning,
            description: "c.Attachment with user-controlled path may cause path traversal",
            cwe: Some("CWE-22"),
        },
        SinkDef {
            name: "inline",
            pattern: SinkKind::MethodCall("Inline"),
            rule_id: "go/echo-path-traversal",
            severity: Severity::Warning,
            description: "c.Inline with user-controlled path may cause path traversal",
            cwe: Some("CWE-22"),
        },
        // Header injection
        SinkDef {
            name: "response_header",
            pattern: SinkKind::MethodCall("Header"),
            rule_id: "go/echo-header-injection",
            severity: Severity::Warning,
            description: "Setting response header with user input may cause header injection",
            cwe: Some("CWE-113"),
        },
    ],

    sanitizers: &[
        // Echo's HTML template rendering uses html/template by default
        SanitizerDef {
            name: "echo_renderer",
            pattern: SanitizerKind::TemplateEngine("echo.Renderer"),
            sanitizes: "html",
            description: "Echo's renderer typically uses html/template with auto-escaping",
        },
        // Bluemonday (commonly used with Echo)
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
        // Validator
        SanitizerDef {
            name: "validator",
            pattern: SanitizerKind::Function("validator.New"),
            sanitizes: "validated",
            description: "Echo validator constrains input format",
        },
    ],

    safe_patterns: &[
        SafePattern {
            name: "echo_json_response",
            pattern: "c.JSON",
            reason: "c.JSON auto-serializes to JSON, preventing XSS",
        },
        SafePattern {
            name: "echo_json_pretty",
            pattern: "c.JSONPretty",
            reason: "c.JSONPretty auto-serializes to JSON with formatting",
        },
        SafePattern {
            name: "echo_xml_response",
            pattern: "c.XML",
            reason: "c.XML auto-serializes to XML with proper encoding",
        },
        SafePattern {
            name: "echo_xml_pretty",
            pattern: "c.XMLPretty",
            reason: "c.XMLPretty auto-serializes to XML with formatting",
        },
        SafePattern {
            name: "echo_blob",
            pattern: "c.Blob",
            reason: "c.Blob sends raw bytes with specified content type",
        },
        SafePattern {
            name: "static_redirect",
            pattern: "c.Redirect(http.StatusFound, \"/",
            reason: "Redirect to hardcoded path starting with / is safe",
        },
        SafePattern {
            name: "echo_stream",
            pattern: "c.Stream",
            reason: "c.Stream for streaming responses with proper content type",
        },
    ],

    dangerous_patterns: &[
        // Render without template
        DangerousPattern {
            name: "render_raw",
            pattern: PatternKind::Construct("c.Render"),
            rule_id: "go/echo-render-review",
            severity: Severity::Info,
            description: "Review c.Render usage for proper escaping",
            cwe: Some("CWE-79"),
        },
        // Raw HTML template
        DangerousPattern {
            name: "raw_html_template",
            pattern: PatternKind::Construct("template.HTML"),
            rule_id: "go/echo-raw-html",
            severity: Severity::Error,
            description: "template.HTML bypasses auto-escaping - XSS risk",
            cwe: Some("CWE-79"),
        },
        // Debug mode
        DangerousPattern {
            name: "debug_mode",
            pattern: PatternKind::Construct("Debug: true"),
            rule_id: "go/echo-debug-mode",
            severity: Severity::Info,
            description: "Ensure Debug mode is disabled in production",
            cwe: None,
        },
        // Missing middleware
        DangerousPattern {
            name: "missing_csrf",
            pattern: PatternKind::Missing("middleware.CSRF"),
            rule_id: "go/echo-missing-csrf",
            severity: Severity::Warning,
            description: "Consider adding CSRF middleware for form submissions",
            cwe: Some("CWE-352"),
        },
        // IP spoofing via proxy headers
        DangerousPattern {
            name: "trust_x_forwarded_for",
            pattern: PatternKind::Construct("IPExtractor"),
            rule_id: "go/echo-ip-spoofing",
            severity: Severity::Warning,
            description: "Review IPExtractor configuration for IP spoofing",
            cwe: Some("CWE-290"),
        },
    ],

    resource_types: &[ResourceType {
        name: "multipart.FileHeader",
        acquire_pattern: "c.FormFile|c.MultipartForm",
        release_pattern: "file.Close()",
        leak_consequence: "Uploaded file handle leak",
    }],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_detection_v4() {
        let content = r#"
            package main
            import "github.com/labstack/echo/v4"
        "#;
        assert!(ECHO_PROFILE.is_active(content));
    }

    #[test]
    fn test_echo_detection_without_version() {
        let content = r#"
            package main
            import "github.com/labstack/echo"
        "#;
        assert!(ECHO_PROFILE.is_active(content));
    }

    #[test]
    fn test_has_query_source() {
        assert!(ECHO_PROFILE.sources.iter().any(|s| s.name == "query_param"));
    }

    #[test]
    fn test_has_param_source() {
        assert!(ECHO_PROFILE.sources.iter().any(|s| s.name == "param"));
    }

    #[test]
    fn test_has_xss_sinks() {
        assert!(ECHO_PROFILE.sinks.iter().any(|s| s.name == "html"));
        assert!(ECHO_PROFILE.sinks.iter().any(|s| s.name == "string"));
    }

    #[test]
    fn test_has_safe_json() {
        assert!(
            ECHO_PROFILE
                .safe_patterns
                .iter()
                .any(|s| s.name == "echo_json_response")
        );
    }
}
