//! Jakarta EE / Servlet API profile
//!
//! Covers Jakarta EE (formerly Java EE) and legacy javax.servlet APIs.
//! This profile handles the foundational Java web APIs that Spring and
//! other frameworks build upon.
//!
//! # Key Security Concerns
//!
//! - **XSS**: response.getWriter().write() with user input
//! - **Open Redirect**: response.sendRedirect() with user-controlled URL
//! - **Path Traversal**: RequestDispatcher with user-controlled path
//! - **Session Fixation**: Session handling without regeneration
//! - **Header Injection**: response.setHeader() with user input

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Jakarta EE / Servlet security profile
pub static JAKARTA_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "jakarta",
    description: "Jakarta EE (Java EE) and Servlet API security patterns",

    detect_imports: &[
        "jakarta.",
        "javax.servlet",
        "import jakarta.",
        "import jakarta.servlet",
        "import javax.servlet",
        "HttpServletRequest",
        "HttpServletResponse",
        "extends HttpServlet",
    ],

    // =========================================================================
    // Sources - Where untrusted data enters via Servlet API
    // =========================================================================
    sources: &[
        // Request parameters
        SourceDef {
            name: "request.getParameter",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getParameter",
            },
            taint_label: "user_input",
            description: "Request parameter - primary source of user input",
        },
        SourceDef {
            name: "request.getParameterValues",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getParameterValues",
            },
            taint_label: "user_input",
            description: "Request parameter array - multi-valued user input",
        },
        SourceDef {
            name: "request.getParameterMap",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getParameterMap",
            },
            taint_label: "user_input",
            description: "All request parameters as map - bulk user input",
        },
        SourceDef {
            name: "request.getParameterNames",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getParameterNames",
            },
            taint_label: "user_input",
            description: "Parameter names enumeration - can be attacker-controlled",
        },
        // HTTP Headers
        SourceDef {
            name: "request.getHeader",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getHeader",
            },
            taint_label: "http_headers",
            description: "HTTP request header - can be manipulated by attacker",
        },
        SourceDef {
            name: "request.getHeaders",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getHeaders",
            },
            taint_label: "http_headers",
            description: "HTTP request headers enumeration",
        },
        SourceDef {
            name: "request.getHeaderNames",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getHeaderNames",
            },
            taint_label: "http_headers",
            description: "HTTP header names enumeration",
        },
        // Cookies
        SourceDef {
            name: "request.getCookies",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getCookies",
            },
            taint_label: "cookie",
            description: "Request cookies - can be modified by attacker",
        },
        // Request body / input stream
        SourceDef {
            name: "request.getInputStream",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getInputStream",
            },
            taint_label: "user_input",
            description: "Request input stream - raw request body",
        },
        SourceDef {
            name: "request.getReader",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getReader",
            },
            taint_label: "user_input",
            description: "Request reader - request body as text",
        },
        // URL components
        SourceDef {
            name: "request.getPathInfo",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getPathInfo",
            },
            taint_label: "url_data",
            description: "URL path info - can be crafted by attacker",
        },
        SourceDef {
            name: "request.getQueryString",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getQueryString",
            },
            taint_label: "user_input",
            description: "Raw query string - unparsed user input",
        },
        SourceDef {
            name: "request.getRequestURI",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getRequestURI",
            },
            taint_label: "url_data",
            description: "Request URI - may contain path traversal",
        },
        SourceDef {
            name: "request.getRequestURL",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getRequestURL",
            },
            taint_label: "url_data",
            description: "Full request URL",
        },
        SourceDef {
            name: "request.getServletPath",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getServletPath",
            },
            taint_label: "url_data",
            description: "Servlet path portion of URL",
        },
        // Multipart / File upload
        SourceDef {
            name: "request.getPart",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getPart",
            },
            taint_label: "user_file",
            description: "Multipart file upload - untrusted file content",
        },
        SourceDef {
            name: "request.getParts",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpServletRequest",
                method: "getParts",
            },
            taint_label: "user_file",
            description: "All multipart uploads",
        },
        // Session attributes (may contain previously tainted data)
        SourceDef {
            name: "session.getAttribute",
            pattern: SourceKind::MethodOnType {
                type_pattern: "HttpSession",
                method: "getAttribute",
            },
            taint_label: "session_data",
            description: "Session attribute - may contain stored user input",
        },
    ],

    // =========================================================================
    // Sinks - Where tainted data becomes dangerous
    // =========================================================================
    sinks: &[
        // XSS via response output
        SinkDef {
            name: "response.getWriter().write",
            pattern: SinkKind::MethodCall("write"),
            rule_id: "java/servlet-xss",
            severity: Severity::Error,
            description: "Tainted data written to response without escaping causes XSS",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "response.getWriter().print",
            pattern: SinkKind::MethodCall("print"),
            rule_id: "java/servlet-xss",
            severity: Severity::Error,
            description: "Tainted data printed to response without escaping causes XSS",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "response.getWriter().println",
            pattern: SinkKind::MethodCall("println"),
            rule_id: "java/servlet-xss",
            severity: Severity::Error,
            description: "Tainted data output to response without escaping",
            cwe: Some("CWE-79"),
        },
        SinkDef {
            name: "response.getOutputStream().write",
            pattern: SinkKind::MethodCall("getOutputStream"),
            rule_id: "java/servlet-xss",
            severity: Severity::Error,
            description: "Binary output with tainted data",
            cwe: Some("CWE-79"),
        },
        // Open redirect
        SinkDef {
            name: "response.sendRedirect",
            pattern: SinkKind::MethodCall("sendRedirect"),
            rule_id: "java/servlet-open-redirect",
            severity: Severity::Error,
            description: "sendRedirect() with tainted URL causes open redirect",
            cwe: Some("CWE-601"),
        },
        // Forward/Include with tainted path
        SinkDef {
            name: "RequestDispatcher.forward",
            pattern: SinkKind::MethodCall("forward"),
            rule_id: "java/servlet-forward-injection",
            severity: Severity::Error,
            description: "RequestDispatcher.forward() with tainted path can expose internal resources",
            cwe: Some("CWE-552"),
        },
        SinkDef {
            name: "RequestDispatcher.include",
            pattern: SinkKind::MethodCall("include"),
            rule_id: "java/servlet-include-injection",
            severity: Severity::Error,
            description: "RequestDispatcher.include() with tainted path can include unintended content",
            cwe: Some("CWE-98"),
        },
        SinkDef {
            name: "request.getRequestDispatcher",
            pattern: SinkKind::MethodCall("getRequestDispatcher"),
            rule_id: "java/servlet-path-manipulation",
            severity: Severity::Warning,
            description: "getRequestDispatcher() with tainted path - validate path before use",
            cwe: Some("CWE-22"),
        },
        // Header injection
        SinkDef {
            name: "response.setHeader",
            pattern: SinkKind::MethodCall("setHeader"),
            rule_id: "java/servlet-header-injection",
            severity: Severity::Warning,
            description: "setHeader() with tainted value may allow header injection",
            cwe: Some("CWE-113"),
        },
        SinkDef {
            name: "response.addHeader",
            pattern: SinkKind::MethodCall("addHeader"),
            rule_id: "java/servlet-header-injection",
            severity: Severity::Warning,
            description: "addHeader() with tainted value may allow header injection",
            cwe: Some("CWE-113"),
        },
        // Cookie manipulation
        SinkDef {
            name: "response.addCookie",
            pattern: SinkKind::MethodCall("addCookie"),
            rule_id: "java/servlet-cookie-manipulation",
            severity: Severity::Warning,
            description: "addCookie() - ensure HttpOnly and Secure flags are set",
            cwe: Some("CWE-614"),
        },
    ],

    // =========================================================================
    // Sanitizers - Functions that neutralize tainted data
    // =========================================================================
    sanitizers: &[
        // OWASP Java Encoder
        SanitizerDef {
            name: "Encode.forHtml",
            pattern: SanitizerKind::Function("Encode.forHtml"),
            sanitizes: "html",
            description: "OWASP Java Encoder for HTML body context",
        },
        SanitizerDef {
            name: "Encode.forHtmlContent",
            pattern: SanitizerKind::Function("Encode.forHtmlContent"),
            sanitizes: "html",
            description: "OWASP Java Encoder for HTML content",
        },
        SanitizerDef {
            name: "Encode.forHtmlAttribute",
            pattern: SanitizerKind::Function("Encode.forHtmlAttribute"),
            sanitizes: "html_attr",
            description: "OWASP Java Encoder for HTML attributes",
        },
        SanitizerDef {
            name: "Encode.forHtmlUnquotedAttribute",
            pattern: SanitizerKind::Function("Encode.forHtmlUnquotedAttribute"),
            sanitizes: "html_attr",
            description: "OWASP Java Encoder for unquoted HTML attributes",
        },
        SanitizerDef {
            name: "Encode.forJavaScript",
            pattern: SanitizerKind::Function("Encode.forJavaScript"),
            sanitizes: "javascript",
            description: "OWASP Java Encoder for JavaScript string context",
        },
        SanitizerDef {
            name: "Encode.forJavaScriptBlock",
            pattern: SanitizerKind::Function("Encode.forJavaScriptBlock"),
            sanitizes: "javascript",
            description: "OWASP Java Encoder for JavaScript block context",
        },
        SanitizerDef {
            name: "Encode.forJavaScriptAttribute",
            pattern: SanitizerKind::Function("Encode.forJavaScriptAttribute"),
            sanitizes: "javascript",
            description: "OWASP Java Encoder for JavaScript in HTML attributes",
        },
        SanitizerDef {
            name: "Encode.forCssString",
            pattern: SanitizerKind::Function("Encode.forCssString"),
            sanitizes: "css",
            description: "OWASP Java Encoder for CSS string context",
        },
        SanitizerDef {
            name: "Encode.forCssUrl",
            pattern: SanitizerKind::Function("Encode.forCssUrl"),
            sanitizes: "css_url",
            description: "OWASP Java Encoder for CSS URL context",
        },
        SanitizerDef {
            name: "Encode.forUri",
            pattern: SanitizerKind::Function("Encode.forUri"),
            sanitizes: "url",
            description: "OWASP Java Encoder for URI encoding",
        },
        SanitizerDef {
            name: "Encode.forUriComponent",
            pattern: SanitizerKind::Function("Encode.forUriComponent"),
            sanitizes: "url",
            description: "OWASP Java Encoder for URI component encoding",
        },
        SanitizerDef {
            name: "Encode.forXml",
            pattern: SanitizerKind::Function("Encode.forXml"),
            sanitizes: "xml",
            description: "OWASP Java Encoder for XML content",
        },
        SanitizerDef {
            name: "Encode.forXmlAttribute",
            pattern: SanitizerKind::Function("Encode.forXmlAttribute"),
            sanitizes: "xml_attr",
            description: "OWASP Java Encoder for XML attributes",
        },
        // Apache Commons Text
        SanitizerDef {
            name: "StringEscapeUtils.escapeHtml4",
            pattern: SanitizerKind::Function("StringEscapeUtils.escapeHtml4"),
            sanitizes: "html",
            description: "Apache Commons Text HTML escaping",
        },
        SanitizerDef {
            name: "StringEscapeUtils.escapeXml11",
            pattern: SanitizerKind::Function("StringEscapeUtils.escapeXml11"),
            sanitizes: "xml",
            description: "Apache Commons Text XML escaping",
        },
        // Jsoup
        SanitizerDef {
            name: "Jsoup.clean",
            pattern: SanitizerKind::Function("Jsoup.clean"),
            sanitizes: "html",
            description: "Jsoup HTML sanitizer with whitelist",
        },
    ],

    // =========================================================================
    // Safe Patterns - Inherently safe constructs
    // =========================================================================
    safe_patterns: &[
        // JSTL
        SafePattern {
            name: "JSTL c:out",
            pattern: "<c:out value=",
            reason: "JSTL c:out tag auto-escapes output by default (escapeXml=true)",
        },
        SafePattern {
            name: "JSTL c:url",
            pattern: "<c:url",
            reason: "JSTL c:url properly encodes URL parameters",
        },
        SafePattern {
            name: "JSTL fn:escapeXml",
            pattern: "fn:escapeXml(",
            reason: "JSTL function explicitly escapes XML/HTML",
        },
        // Content-Type restrictions
        SafePattern {
            name: "JSON Content-Type",
            pattern: "application/json",
            reason: "JSON responses are not rendered as HTML",
        },
        SafePattern {
            name: "Content-Type header set",
            pattern: "setContentType(\"text/plain\")",
            reason: "Plain text Content-Type prevents HTML rendering",
        },
        // Validation patterns
        SafePattern {
            name: "URL validation",
            pattern: "startsWith(\"/\")",
            reason: "Relative URL validation prevents open redirect",
        },
        SafePattern {
            name: "Whitelist check",
            pattern: "allowedUrls.contains",
            reason: "Whitelist validation prevents open redirect",
        },
    ],

    // =========================================================================
    // Dangerous Patterns - Security anti-patterns
    // =========================================================================
    dangerous_patterns: &[
        // JSP scriptlet XSS
        DangerousPattern {
            name: "JSP scriptlet output",
            pattern: PatternKind::Regex(r"<%=\s*request\.getParameter"),
            rule_id: "java/jsp-xss",
            severity: Severity::Critical,
            description: "JSP scriptlet directly outputting request parameter - use c:out instead",
            cwe: Some("CWE-79"),
        },
        DangerousPattern {
            name: "JSP EL unescaped param",
            pattern: PatternKind::Regex(r"\$\{param\."),
            rule_id: "java/jsp-el-xss",
            severity: Severity::Error,
            description: "EL expression ${param.x} outputs unescaped - use fn:escapeXml()",
            cwe: Some("CWE-79"),
        },
        DangerousPattern {
            name: "JSP EL unescaped request",
            pattern: PatternKind::Regex(r"\$\{requestScope\."),
            rule_id: "java/jsp-el-xss",
            severity: Severity::Warning,
            description: "EL expression with request data - ensure escaping",
            cwe: Some("CWE-79"),
        },
        // Cookie security
        DangerousPattern {
            name: "Cookie without HttpOnly",
            pattern: PatternKind::Missing("setHttpOnly(true)"),
            rule_id: "java/servlet-cookie-httponly",
            severity: Severity::Warning,
            description: "Cookie should have HttpOnly flag to prevent XSS cookie theft",
            cwe: Some("CWE-1004"),
        },
        DangerousPattern {
            name: "Cookie without Secure",
            pattern: PatternKind::Missing("setSecure(true)"),
            rule_id: "java/servlet-cookie-secure",
            severity: Severity::Warning,
            description: "Cookie should have Secure flag for HTTPS-only transmission",
            cwe: Some("CWE-614"),
        },
        // Session security
        DangerousPattern {
            name: "Session without regeneration",
            pattern: PatternKind::Missing("changeSessionId"),
            rule_id: "java/servlet-session-fixation",
            severity: Severity::Warning,
            description: "Regenerate session ID after authentication to prevent session fixation",
            cwe: Some("CWE-384"),
        },
        // Direct path usage
        DangerousPattern {
            name: "getRequestDispatcher with concat",
            pattern: PatternKind::Regex(r#"getRequestDispatcher\([^)]*\+"#),
            rule_id: "java/servlet-path-traversal",
            severity: Severity::Error,
            description: "RequestDispatcher with string concatenation - validate path",
            cwe: Some("CWE-22"),
        },
        // Error page information disclosure
        DangerousPattern {
            name: "Exception in response",
            pattern: PatternKind::Regex(r"printStackTrace\(\s*response\.getWriter"),
            rule_id: "java/servlet-info-disclosure",
            severity: Severity::Error,
            description: "Stack trace in response discloses internal information",
            cwe: Some("CWE-209"),
        },
        // Header injection via newlines
        DangerousPattern {
            name: "CRLF in header",
            pattern: PatternKind::Regex(r#"setHeader\([^)]*\\r|\\n"#),
            rule_id: "java/servlet-crlf-injection",
            severity: Severity::Critical,
            description: "CRLF characters in headers enable response splitting",
            cwe: Some("CWE-113"),
        },
    ],

    // =========================================================================
    // Resource Types - Resources requiring proper lifecycle
    // =========================================================================
    resource_types: &[
        ResourceType {
            name: "HttpSession",
            acquire_pattern: "request.getSession() | request.getSession(true)",
            release_pattern: "session.invalidate()",
            leak_consequence: "Session data persists, memory leak, session fixation risk",
        },
        ResourceType {
            name: "ServletInputStream",
            acquire_pattern: "request.getInputStream()",
            release_pattern: "close() | try-with-resources",
            leak_consequence: "Request body cannot be re-read, potential memory leak",
        },
        ResourceType {
            name: "ServletOutputStream",
            acquire_pattern: "response.getOutputStream()",
            release_pattern: "close() | flush()",
            leak_consequence: "Response not sent, client timeout",
        },
        ResourceType {
            name: "PrintWriter",
            acquire_pattern: "response.getWriter()",
            release_pattern: "close() | flush()",
            leak_consequence: "Response not sent to client",
        },
        ResourceType {
            name: "Part (file upload)",
            acquire_pattern: "request.getPart() | request.getParts()",
            release_pattern: "delete()",
            leak_consequence: "Temporary files not cleaned up, disk space exhaustion",
        },
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jakarta_detection() {
        assert!(JAKARTA_PROFILE.is_active("import jakarta.servlet.http.HttpServletRequest;"));
        assert!(JAKARTA_PROFILE.is_active("import javax.servlet.http.HttpServletRequest;"));
        assert!(JAKARTA_PROFILE.is_active("import jakarta.servlet.*;"));
        assert!(JAKARTA_PROFILE.is_active("extends HttpServlet"));
        assert!(!JAKARTA_PROFILE.is_active("import org.springframework.web.*;"));
    }

    #[test]
    fn test_jakarta_has_sources() {
        assert!(!JAKARTA_PROFILE.sources.is_empty());

        let source_names: Vec<&str> = JAKARTA_PROFILE.sources.iter().map(|s| s.name).collect();
        assert!(source_names.contains(&"request.getParameter"));
        assert!(source_names.contains(&"request.getHeader"));
        assert!(source_names.contains(&"request.getCookies"));
        assert!(source_names.contains(&"request.getInputStream"));
        assert!(source_names.contains(&"request.getPathInfo"));
        assert!(source_names.contains(&"request.getQueryString"));
    }

    #[test]
    fn test_jakarta_has_sinks() {
        assert!(!JAKARTA_PROFILE.sinks.is_empty());

        let sink_names: Vec<&str> = JAKARTA_PROFILE.sinks.iter().map(|s| s.name).collect();
        assert!(sink_names.iter().any(|n| n.contains("getWriter")));
        assert!(sink_names.iter().any(|n| n.contains("sendRedirect")));
        assert!(sink_names.iter().any(|n| n.contains("forward")));
        assert!(sink_names.iter().any(|n| n.contains("include")));
    }

    #[test]
    fn test_jakarta_has_sanitizers() {
        assert!(!JAKARTA_PROFILE.sanitizers.is_empty());

        let sanitizer_names: Vec<&str> =
            JAKARTA_PROFILE.sanitizers.iter().map(|s| s.name).collect();
        assert!(sanitizer_names.iter().any(|n| n.contains("Encode")));
        assert!(sanitizer_names.iter().any(|n| n.contains("Jsoup")));
    }

    #[test]
    fn test_jakarta_dangerous_patterns() {
        assert!(!JAKARTA_PROFILE.dangerous_patterns.is_empty());

        let pattern_names: Vec<&str> = JAKARTA_PROFILE
            .dangerous_patterns
            .iter()
            .map(|p| p.name)
            .collect();
        assert!(pattern_names.iter().any(|n| n.contains("JSP")));
        assert!(pattern_names.iter().any(|n| n.contains("Cookie")));
    }
}
