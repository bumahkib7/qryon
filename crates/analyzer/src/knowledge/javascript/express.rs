//! Express.js framework security knowledge
//!
//! Defines taint sources, sinks, and sanitizers for Express.js web framework.
//! Express is the most popular Node.js web framework.
//!
//! NOTE: This module DETECTS security vulnerabilities - it does not contain them.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Express.js framework security profile
pub static EXPRESS_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "express",
    description: "Express.js web framework for Node.js",
    detect_imports: &[
        "require('express')",
        "from 'express'",
        "import express",
        "require(\"express\")",
        "from \"express\"",
    ],
    sources: &EXPRESS_SOURCES,
    sinks: &EXPRESS_SINKS,
    sanitizers: &EXPRESS_SANITIZERS,
    safe_patterns: &EXPRESS_SAFE_PATTERNS,
    dangerous_patterns: &EXPRESS_DANGEROUS_PATTERNS,
    resource_types: &EXPRESS_RESOURCES,
};

/// Taint sources - user input from HTTP requests
static EXPRESS_SOURCES: [SourceDef; 20] = [
    // Query parameters
    SourceDef {
        name: "req.query",
        pattern: SourceKind::MemberAccess("req.query"),
        taint_label: "query_params",
        description: "URL query string parameters - attacker controlled",
    },
    SourceDef {
        name: "request.query",
        pattern: SourceKind::MemberAccess("request.query"),
        taint_label: "query_params",
        description: "URL query string parameters - attacker controlled",
    },
    // Route parameters
    SourceDef {
        name: "req.params",
        pattern: SourceKind::MemberAccess("req.params"),
        taint_label: "route_params",
        description: "Route path parameters - attacker controlled",
    },
    SourceDef {
        name: "request.params",
        pattern: SourceKind::MemberAccess("request.params"),
        taint_label: "route_params",
        description: "Route path parameters - attacker controlled",
    },
    // Request body
    SourceDef {
        name: "req.body",
        pattern: SourceKind::MemberAccess("req.body"),
        taint_label: "request_body",
        description: "Parsed request body (JSON, form data) - attacker controlled",
    },
    SourceDef {
        name: "request.body",
        pattern: SourceKind::MemberAccess("request.body"),
        taint_label: "request_body",
        description: "Parsed request body - attacker controlled",
    },
    // Headers
    SourceDef {
        name: "req.headers",
        pattern: SourceKind::MemberAccess("req.headers"),
        taint_label: "http_headers",
        description: "HTTP request headers - attacker controlled",
    },
    SourceDef {
        name: "req.header()",
        pattern: SourceKind::FunctionCall("req.header"),
        taint_label: "http_headers",
        description: "Get specific HTTP header - attacker controlled",
    },
    SourceDef {
        name: "req.get()",
        pattern: SourceKind::FunctionCall("req.get"),
        taint_label: "http_headers",
        description: "Get HTTP header (alias for header()) - attacker controlled",
    },
    // Cookies
    SourceDef {
        name: "req.cookies",
        pattern: SourceKind::MemberAccess("req.cookies"),
        taint_label: "cookies",
        description: "Parsed cookies (requires cookie-parser) - attacker controlled",
    },
    SourceDef {
        name: "req.signedCookies",
        pattern: SourceKind::MemberAccess("req.signedCookies"),
        taint_label: "cookies",
        description: "Signed cookies - validated but still user-provided data",
    },
    // URL/path
    SourceDef {
        name: "req.path",
        pattern: SourceKind::MemberAccess("req.path"),
        taint_label: "url_path",
        description: "URL path portion - attacker controlled",
    },
    SourceDef {
        name: "req.url",
        pattern: SourceKind::MemberAccess("req.url"),
        taint_label: "url",
        description: "Full request URL - attacker controlled",
    },
    SourceDef {
        name: "req.originalUrl",
        pattern: SourceKind::MemberAccess("req.originalUrl"),
        taint_label: "url",
        description: "Original request URL before routing - attacker controlled",
    },
    SourceDef {
        name: "req.baseUrl",
        pattern: SourceKind::MemberAccess("req.baseUrl"),
        taint_label: "url",
        description: "Base URL of router - partially attacker controlled",
    },
    // Hostname
    SourceDef {
        name: "req.hostname",
        pattern: SourceKind::MemberAccess("req.hostname"),
        taint_label: "hostname",
        description: "Request hostname from Host header - attacker controlled",
    },
    SourceDef {
        name: "req.subdomains",
        pattern: SourceKind::MemberAccess("req.subdomains"),
        taint_label: "hostname",
        description: "Array of subdomains - attacker controlled",
    },
    // Files (multer)
    SourceDef {
        name: "req.file",
        pattern: SourceKind::MemberAccess("req.file"),
        taint_label: "file_upload",
        description: "Uploaded file (multer single) - completely untrusted",
    },
    SourceDef {
        name: "req.files",
        pattern: SourceKind::MemberAccess("req.files"),
        taint_label: "file_upload",
        description: "Uploaded files (multer array) - completely untrusted",
    },
    // Protocol
    SourceDef {
        name: "req.protocol",
        pattern: SourceKind::MemberAccess("req.protocol"),
        taint_label: "protocol",
        description: "Request protocol - can be spoofed via headers",
    },
];

/// Dangerous sinks - response methods and other dangerous operations
static EXPRESS_SINKS: [SinkDef; 14] = [
    // Response body sinks - potential XSS
    SinkDef {
        name: "res.send",
        pattern: SinkKind::MethodCall("send"),
        rule_id: "express/xss",
        severity: Severity::Warning,
        description: "Detects response body output - potential XSS if HTML",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "res.write",
        pattern: SinkKind::MethodCall("write"),
        rule_id: "express/xss",
        severity: Severity::Warning,
        description: "Detects raw response write - potential XSS",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "res.end",
        pattern: SinkKind::MethodCall("end"),
        rule_id: "express/xss",
        severity: Severity::Warning,
        description: "Detects response end with data - potential XSS",
        cwe: Some("CWE-79"),
    },
    // Template rendering - potential SSTI
    SinkDef {
        name: "res.render",
        pattern: SinkKind::MethodCall("render"),
        rule_id: "express/template-injection",
        severity: Severity::Error,
        description: "Detects template rendering - verify template name and data are safe",
        cwe: Some("CWE-94"),
    },
    // Redirect - potential open redirect
    SinkDef {
        name: "res.redirect",
        pattern: SinkKind::MethodCall("redirect"),
        rule_id: "express/open-redirect",
        severity: Severity::Error,
        description: "Detects redirect - potential open redirect with user input",
        cwe: Some("CWE-601"),
    },
    SinkDef {
        name: "res.location",
        pattern: SinkKind::MethodCall("location"),
        rule_id: "express/open-redirect",
        severity: Severity::Warning,
        description: "Detects Location header - potential open redirect",
        cwe: Some("CWE-601"),
    },
    // Header injection
    SinkDef {
        name: "res.set",
        pattern: SinkKind::MethodCall("set"),
        rule_id: "express/header-injection",
        severity: Severity::Warning,
        description: "Detects header setting - potential header injection",
        cwe: Some("CWE-113"),
    },
    SinkDef {
        name: "res.setHeader",
        pattern: SinkKind::MethodCall("setHeader"),
        rule_id: "express/header-injection",
        severity: Severity::Warning,
        description: "Detects header setting - potential header injection",
        cwe: Some("CWE-113"),
    },
    SinkDef {
        name: "res.append",
        pattern: SinkKind::MethodCall("append"),
        rule_id: "express/header-injection",
        severity: Severity::Warning,
        description: "Detects header append - potential header injection",
        cwe: Some("CWE-113"),
    },
    // Cookie setting
    SinkDef {
        name: "res.cookie",
        pattern: SinkKind::MethodCall("cookie"),
        rule_id: "express/cookie-injection",
        severity: Severity::Warning,
        description: "Detects cookie setting - verify name and value are safe",
        cwe: Some("CWE-614"),
    },
    // File operations - path traversal
    SinkDef {
        name: "res.sendFile",
        pattern: SinkKind::MethodCall("sendFile"),
        rule_id: "express/path-traversal",
        severity: Severity::Error,
        description: "Detects file serving - potential path traversal",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "res.download",
        pattern: SinkKind::MethodCall("download"),
        rule_id: "express/path-traversal",
        severity: Severity::Error,
        description: "Detects file download - potential path traversal",
        cwe: Some("CWE-22"),
    },
    // JSON/JSONP
    SinkDef {
        name: "res.json",
        pattern: SinkKind::MethodCall("json"),
        rule_id: "express/json-injection",
        severity: Severity::Info,
        description: "Detects JSON response - safe but data may leak sensitive info",
        cwe: None,
    },
    SinkDef {
        name: "res.jsonp",
        pattern: SinkKind::MethodCall("jsonp"),
        rule_id: "express/jsonp-callback",
        severity: Severity::Warning,
        description: "Detects JSONP response - callback parameter can enable XSS",
        cwe: Some("CWE-79"),
    },
];

/// Sanitizers - functions that neutralize tainted data
static EXPRESS_SANITIZERS: [SanitizerDef; 12] = [
    // express-validator
    SanitizerDef {
        name: "validator.escape",
        pattern: SanitizerKind::Function("escape"),
        sanitizes: "html",
        description: "HTML entity encoding from express-validator",
    },
    SanitizerDef {
        name: "validator.trim",
        pattern: SanitizerKind::Function("trim"),
        sanitizes: "whitespace",
        description: "Whitespace trimming",
    },
    SanitizerDef {
        name: "validator.normalizeEmail",
        pattern: SanitizerKind::Function("normalizeEmail"),
        sanitizes: "email",
        description: "Email normalization",
    },
    SanitizerDef {
        name: "validator.toInt",
        pattern: SanitizerKind::Function("toInt"),
        sanitizes: "numeric",
        description: "Convert to integer - removes non-numeric content",
    },
    SanitizerDef {
        name: "validator.toFloat",
        pattern: SanitizerKind::Function("toFloat"),
        sanitizes: "numeric",
        description: "Convert to float - removes non-numeric content",
    },
    SanitizerDef {
        name: "validator.toBoolean",
        pattern: SanitizerKind::Function("toBoolean"),
        sanitizes: "boolean",
        description: "Convert to boolean",
    },
    // Helmet middleware
    SanitizerDef {
        name: "helmet",
        pattern: SanitizerKind::Function("helmet"),
        sanitizes: "headers",
        description: "Security headers middleware - adds CSP, etc.",
    },
    // General sanitizers
    SanitizerDef {
        name: "DOMPurify.sanitize",
        pattern: SanitizerKind::Function("sanitize"),
        sanitizes: "html",
        description: "DOMPurify HTML sanitization - safe for innerHTML",
    },
    SanitizerDef {
        name: "sanitize-html",
        pattern: SanitizerKind::Function("sanitizeHtml"),
        sanitizes: "html",
        description: "sanitize-html package - safe for HTML output",
    },
    SanitizerDef {
        name: "xss",
        pattern: SanitizerKind::Function("xss"),
        sanitizes: "html",
        description: "xss package - HTML filtering",
    },
    // Encoding
    SanitizerDef {
        name: "encodeURIComponent",
        pattern: SanitizerKind::Function("encodeURIComponent"),
        sanitizes: "url",
        description: "URL component encoding",
    },
    SanitizerDef {
        name: "encodeURI",
        pattern: SanitizerKind::Function("encodeURI"),
        sanitizes: "url",
        description: "Full URL encoding",
    },
];

/// Safe patterns - inherently safe Express patterns
static EXPRESS_SAFE_PATTERNS: [SafePattern; 6] = [
    SafePattern {
        name: "res.json",
        pattern: "res.json(data)",
        reason: "JSON serialization auto-escapes strings for JSON context",
    },
    SafePattern {
        name: "res.sendStatus",
        pattern: "res.sendStatus(code)",
        reason: "Only sends status code with standard message",
    },
    SafePattern {
        name: "express.static",
        pattern: "express.static(rootDir)",
        reason: "Static file serving with built-in path traversal protection",
    },
    SafePattern {
        name: "path.join_root",
        pattern: "res.sendFile(path.join(__dirname, userFile))",
        reason: "path.join normalizes but still needs basename or validation",
    },
    SafePattern {
        name: "relative_redirect",
        pattern: "res.redirect('/fixed/path')",
        reason: "Relative redirects within same origin are safe",
    },
    SafePattern {
        name: "express_validator",
        pattern: "check('field').escape()",
        reason: "express-validator escapes prevent XSS",
    },
];

/// Dangerous patterns in Express applications
static EXPRESS_DANGEROUS_PATTERNS: [DangerousPattern; 8] = [
    DangerousPattern {
        name: "raw_query_in_render",
        pattern: PatternKind::Construct("res.render(req.query.template)"),
        rule_id: "express/template-injection",
        severity: Severity::Critical,
        description: "Detects user-controlled template name - server-side template injection",
        cwe: Some("CWE-94"),
    },
    DangerousPattern {
        name: "raw_body_in_html",
        pattern: PatternKind::Construct("res.send('<html>' + req.body"),
        rule_id: "express/xss",
        severity: Severity::Critical,
        description: "Detects raw user input in HTML response - XSS",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "unchecked_redirect",
        pattern: PatternKind::Construct("res.redirect(req.query.url)"),
        rule_id: "express/open-redirect",
        severity: Severity::Error,
        description: "Detects unvalidated redirect URL - open redirect",
        cwe: Some("CWE-601"),
    },
    DangerousPattern {
        name: "file_from_params",
        pattern: PatternKind::Construct("res.sendFile(req.params.file)"),
        rule_id: "express/path-traversal",
        severity: Severity::Critical,
        description: "Detects user-controlled file path - path traversal",
        cwe: Some("CWE-22"),
    },
    DangerousPattern {
        name: "no_csrf_protection",
        pattern: PatternKind::Missing("csurf"),
        rule_id: "express/no-csrf",
        severity: Severity::Warning,
        description: "Detects missing CSRF protection on state-changing routes",
        cwe: Some("CWE-352"),
    },
    DangerousPattern {
        name: "trust_proxy_all",
        pattern: PatternKind::Construct("app.set('trust proxy', true)"),
        rule_id: "express/trust-proxy",
        severity: Severity::Warning,
        description: "Detects trusting all proxies - specify trusted proxy addresses",
        cwe: None,
    },
    DangerousPattern {
        name: "disabled_security",
        pattern: PatternKind::Construct("app.disable('x-powered-by')"),
        rule_id: "express/security-headers",
        severity: Severity::Info,
        description: "Good: Disabled x-powered-by header",
        cwe: None,
    },
    DangerousPattern {
        name: "jsonp_enabled",
        pattern: PatternKind::Construct("res.jsonp"),
        rule_id: "express/jsonp",
        severity: Severity::Warning,
        description: "Detects JSONP usage - prefer CORS for cross-origin requests",
        cwe: Some("CWE-79"),
    },
];

/// Express-specific resources
static EXPRESS_RESOURCES: [ResourceType; 2] = [
    ResourceType {
        name: "ExpressApp",
        acquire_pattern: "express()",
        release_pattern: "server.close()",
        leak_consequence: "Server port binding - prevents restart",
    },
    ResourceType {
        name: "MulterUpload",
        acquire_pattern: "multer({ dest: ... })",
        release_pattern: "fs.unlink(req.file.path)",
        leak_consequence: "Temporary file accumulation",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_detection() {
        assert!(EXPRESS_PROFILE.is_active("const express = require('express');"));
        assert!(EXPRESS_PROFILE.is_active("import express from 'express';"));
        assert!(EXPRESS_PROFILE.is_active("import { Router } from 'express';"));
        assert!(!EXPRESS_PROFILE.is_active("import React from 'react';"));
    }

    #[test]
    fn test_sources() {
        assert!(!EXPRESS_SOURCES.is_empty());
        assert!(EXPRESS_SOURCES.iter().any(|s| s.name == "req.query"));
        assert!(EXPRESS_SOURCES.iter().any(|s| s.name == "req.body"));
        assert!(EXPRESS_SOURCES.iter().any(|s| s.name == "req.params"));
    }

    #[test]
    fn test_sinks() {
        assert!(!EXPRESS_SINKS.is_empty());
        assert!(EXPRESS_SINKS.iter().any(|s| s.name == "res.send"));
        assert!(EXPRESS_SINKS.iter().any(|s| s.name == "res.redirect"));
    }

    #[test]
    fn test_sanitizers() {
        assert!(!EXPRESS_SANITIZERS.is_empty());
        assert!(
            EXPRESS_SANITIZERS
                .iter()
                .any(|s| s.name == "validator.escape")
        );
    }
}
