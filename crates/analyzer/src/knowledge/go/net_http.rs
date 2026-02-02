//! Go net/http framework profile
//!
//! Security knowledge for Go's standard library HTTP package.
//! This is the foundation that most Go web frameworks build upon.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Go net/http standard library profile
pub static NET_HTTP_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "net/http",
    description: "Go standard library HTTP package - foundation for web servers and clients",
    detect_imports: &["net/http", "\"net/http\""],

    sources: &[
        // URL query parameters
        SourceDef {
            name: "url_query",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*http.Request",
                method: "URL.Query",
            },
            taint_label: "user_input",
            description: "Query parameters from URL - user controllable",
        },
        SourceDef {
            name: "url_query_get",
            pattern: SourceKind::MemberAccess("r.URL.Query().Get"),
            taint_label: "user_input",
            description: "Single query parameter - user controllable",
        },
        // Form values
        SourceDef {
            name: "form_value",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*http.Request",
                method: "FormValue",
            },
            taint_label: "user_input",
            description: "Form field value - user controllable",
        },
        SourceDef {
            name: "post_form_value",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*http.Request",
                method: "PostFormValue",
            },
            taint_label: "user_input",
            description: "POST form field value - user controllable",
        },
        // Headers
        SourceDef {
            name: "header_get",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*http.Request",
                method: "Header.Get",
            },
            taint_label: "user_input",
            description: "HTTP header value - can be user controllable",
        },
        // Request body
        SourceDef {
            name: "request_body",
            pattern: SourceKind::MemberAccess("r.Body"),
            taint_label: "user_input",
            description: "Request body - user controllable content",
        },
        // URL path
        SourceDef {
            name: "url_path",
            pattern: SourceKind::MemberAccess("r.URL.Path"),
            taint_label: "user_input",
            description: "URL path - can be user controllable",
        },
        // Cookies
        SourceDef {
            name: "cookie",
            pattern: SourceKind::MethodOnType {
                type_pattern: "*http.Request",
                method: "Cookie",
            },
            taint_label: "user_input",
            description: "Cookie value - user controllable",
        },
        // Remote address (for logging, not auth)
        SourceDef {
            name: "remote_addr",
            pattern: SourceKind::MemberAccess("r.RemoteAddr"),
            taint_label: "untrusted_metadata",
            description: "Remote address - can be spoofed via proxy headers",
        },
    ],

    sinks: &[
        // XSS sinks
        SinkDef {
            name: "fprintf_response",
            pattern: SinkKind::FunctionCall("fmt.Fprintf"),
            rule_id: "go/xss-response-write",
            severity: Severity::Error,
            description: "Writing user input directly to response can cause XSS",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "response_write",
            pattern: SinkKind::MethodCall("Write"),
            rule_id: "go/xss-response-write",
            severity: Severity::Warning,
            description: "ResponseWriter.Write with user input may cause XSS",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "response_writestring",
            pattern: SinkKind::MethodCall("WriteString"),
            rule_id: "go/xss-response-write",
            severity: Severity::Warning,
            description: "ResponseWriter.WriteString with user input may cause XSS",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "template_html",
            pattern: SinkKind::FunctionCall("template.HTML"),
            rule_id: "go/xss-template-html",
            severity: Severity::Critical,
            description: "template.HTML bypasses auto-escaping - XSS if user input",
            cwe: Some("CWE-79"),
        },
        // Open redirect
        SinkDef {
            name: "http_redirect",
            pattern: SinkKind::FunctionCall("http.Redirect"),
            rule_id: "go/open-redirect",
            severity: Severity::Warning,
            description: "http.Redirect with user-controlled URL may cause open redirect",
            cwe: Some("CWE-601"),
        },
        // SSRF
        SinkDef {
            name: "http_get",
            pattern: SinkKind::FunctionCall("http.Get"),
            rule_id: "go/ssrf",
            severity: Severity::Warning,
            description: "http.Get with user-controlled URL may cause SSRF",
            cwe: Some("CWE-918"),
        },
        SinkDef {
            name: "http_post",
            pattern: SinkKind::FunctionCall("http.Post"),
            rule_id: "go/ssrf",
            severity: Severity::Warning,
            description: "http.Post with user-controlled URL may cause SSRF",
            cwe: Some("CWE-918"),
        },
        SinkDef {
            name: "http_newrequest",
            pattern: SinkKind::FunctionCall("http.NewRequest"),
            rule_id: "go/ssrf",
            severity: Severity::Warning,
            description: "http.NewRequest with user-controlled URL may cause SSRF",
            cwe: Some("CWE-918"),
        },
    ],

    sanitizers: &[
        // HTML escaping
        SanitizerDef {
            name: "html_escape_string",
            pattern: SanitizerKind::Function("html.EscapeString"),
            sanitizes: "html",
            description: "Escapes HTML special characters",
        },
        // URL escaping
        SanitizerDef {
            name: "url_query_escape",
            pattern: SanitizerKind::Function("url.QueryEscape"),
            sanitizes: "url",
            description: "URL-encodes a string for use in query parameters",
        },
        SanitizerDef {
            name: "url_path_escape",
            pattern: SanitizerKind::Function("url.PathEscape"),
            sanitizes: "url_path",
            description: "URL-encodes a string for use in path segments",
        },
        // Template auto-escaping
        SanitizerDef {
            name: "html_template",
            pattern: SanitizerKind::TemplateEngine("html/template"),
            sanitizes: "html",
            description: "html/template package provides automatic context-aware escaping",
        },
    ],

    safe_patterns: &[
        SafePattern {
            name: "html_template_auto_escape",
            pattern: "html/template",
            reason: "html/template automatically escapes values based on context",
        },
        SafePattern {
            name: "static_redirect",
            pattern: "http.Redirect(w, r, \"/fixed-path\"",
            reason: "Redirect to a hardcoded path is safe",
        },
    ],

    dangerous_patterns: &[
        // text/template with user input (no auto-escaping)
        DangerousPattern {
            name: "text_template_user_input",
            pattern: PatternKind::Construct("text/template"),
            rule_id: "go/text-template-xss",
            severity: Severity::Warning,
            description: "text/template does not auto-escape HTML - use html/template for web content",
            cwe: Some("CWE-79"),
        },
        // Discarded error from HTTP operations
        DangerousPattern {
            name: "discarded_http_error",
            pattern: PatternKind::Regex(r#"http\.(Get|Post|Do)\([^)]+\)\s*[^,]"#),
            rule_id: "go/unchecked-http-error",
            severity: Severity::Warning,
            description: "HTTP operation error should be checked",
            cwe: Some("CWE-252"),
        },
        // Insecure TLS config
        DangerousPattern {
            name: "insecure_tls",
            pattern: PatternKind::Construct("InsecureSkipVerify: true"),
            rule_id: "go/insecure-tls",
            severity: Severity::Error,
            description: "InsecureSkipVerify disables TLS certificate validation",
            cwe: Some("CWE-295"),
        },
        // Timing attack on password comparison
        DangerousPattern {
            name: "password_comparison",
            pattern: PatternKind::Regex(r#"password\s*==\s*|==\s*password"#),
            rule_id: "go/timing-attack",
            severity: Severity::Warning,
            description: "Use subtle.ConstantTimeCompare for password comparison",
            cwe: Some("CWE-208"),
        },
    ],

    resource_types: &[
        ResourceType {
            name: "*os.File",
            acquire_pattern: "os.Open|os.Create|os.OpenFile",
            release_pattern: "Close()",
            leak_consequence: "File descriptor leak - can exhaust system resources",
        },
        ResourceType {
            name: "*http.Response.Body",
            acquire_pattern: "http.Get|http.Post|http.Do|Client.Do",
            release_pattern: "Close()",
            leak_consequence: "Connection leak - can exhaust connection pool",
        },
        ResourceType {
            name: "context.CancelFunc",
            acquire_pattern: "context.WithCancel|context.WithTimeout|context.WithDeadline",
            release_pattern: "cancel()",
            leak_consequence: "Context leak - goroutine and memory leak",
        },
        ResourceType {
            name: "sync.Mutex",
            acquire_pattern: "Lock()",
            release_pattern: "Unlock()",
            leak_consequence: "Deadlock - program hangs",
        },
        ResourceType {
            name: "sync.RWMutex",
            acquire_pattern: "Lock()|RLock()",
            release_pattern: "Unlock()|RUnlock()",
            leak_consequence: "Deadlock - program hangs",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_net_http_detection() {
        let content = r#"
            package main
            import "net/http"
        "#;
        assert!(NET_HTTP_PROFILE.is_active(content));
    }

    #[test]
    fn test_has_sources() {
        assert!(!NET_HTTP_PROFILE.sources.is_empty());
        // Should have common sources
        assert!(
            NET_HTTP_PROFILE
                .sources
                .iter()
                .any(|s| s.name == "form_value")
        );
    }

    #[test]
    fn test_has_sinks() {
        assert!(!NET_HTTP_PROFILE.sinks.is_empty());
        // Should have XSS sink
        assert!(
            NET_HTTP_PROFILE
                .sinks
                .iter()
                .any(|s| s.name == "template_html")
        );
    }

    #[test]
    fn test_has_sanitizers() {
        assert!(!NET_HTTP_PROFILE.sanitizers.is_empty());
        // Should have HTML escape
        assert!(
            NET_HTTP_PROFILE
                .sanitizers
                .iter()
                .any(|s| s.name == "html_escape_string")
        );
    }
}
