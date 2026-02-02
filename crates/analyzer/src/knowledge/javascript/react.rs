//! React framework security knowledge
//!
//! Defines taint sources, sinks, and sanitizers for React applications.
//! React's virtual DOM and JSX provide automatic XSS protection for most
//! cases, but there are still dangerous patterns to detect.
//!
//! NOTE: This module DETECTS security vulnerabilities - it does not contain them.
//! The patterns here are used to identify dangerous code during static analysis.
//! This is a security ANALYZER, not exploitable code.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// React framework security profile
pub static REACT_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "react",
    description: "React library for building user interfaces",
    detect_imports: &[
        "from 'react'",
        "from \"react\"",
        "require('react')",
        "require(\"react\")",
        "from 'react-dom'",
        "from \"react-dom\"",
        "import React",
    ],
    sources: &REACT_SOURCES,
    sinks: &REACT_SINKS,
    sanitizers: &REACT_SANITIZERS,
    safe_patterns: &REACT_SAFE_PATTERNS,
    dangerous_patterns: &REACT_DANGEROUS_PATTERNS,
    resource_types: &REACT_RESOURCES,
};

/// Taint sources - where untrusted data enters React applications
static REACT_SOURCES: [SourceDef; 16] = [
    // Props - data from parent components
    SourceDef {
        name: "props",
        pattern: SourceKind::MemberAccess("props"),
        taint_label: "component_props",
        description: "Component props - may contain user data",
    },
    SourceDef {
        name: "this.props",
        pattern: SourceKind::MemberAccess("this.props"),
        taint_label: "component_props",
        description: "Class component props - may contain user data",
    },
    // React Router hooks
    SourceDef {
        name: "useSearchParams",
        pattern: SourceKind::FunctionCall("useSearchParams"),
        taint_label: "url_params",
        description: "URL search parameters - attacker controlled",
    },
    SourceDef {
        name: "useParams",
        pattern: SourceKind::FunctionCall("useParams"),
        taint_label: "route_params",
        description: "Route parameters - attacker controlled",
    },
    SourceDef {
        name: "useLocation",
        pattern: SourceKind::FunctionCall("useLocation"),
        taint_label: "location",
        description: "Location object - may contain attacker controlled data",
    },
    // Browser APIs
    SourceDef {
        name: "window.location",
        pattern: SourceKind::MemberAccess("window.location"),
        taint_label: "url_data",
        description: "Browser location - attacker controlled via URL",
    },
    SourceDef {
        name: "location.search",
        pattern: SourceKind::MemberAccess("location.search"),
        taint_label: "query_string",
        description: "URL query string - attacker controlled",
    },
    SourceDef {
        name: "location.hash",
        pattern: SourceKind::MemberAccess("location.hash"),
        taint_label: "url_hash",
        description: "URL hash - attacker controlled",
    },
    SourceDef {
        name: "location.pathname",
        pattern: SourceKind::MemberAccess("location.pathname"),
        taint_label: "url_path",
        description: "URL path - attacker controlled",
    },
    SourceDef {
        name: "URLSearchParams",
        pattern: SourceKind::FunctionCall("URLSearchParams"),
        taint_label: "url_params",
        description: "Parsed URL parameters - attacker controlled",
    },
    // Storage
    SourceDef {
        name: "localStorage.getItem",
        pattern: SourceKind::FunctionCall("localStorage.getItem"),
        taint_label: "storage",
        description: "Local storage - persisted user data",
    },
    SourceDef {
        name: "sessionStorage.getItem",
        pattern: SourceKind::FunctionCall("sessionStorage.getItem"),
        taint_label: "storage",
        description: "Session storage - temporary user data",
    },
    // User input
    SourceDef {
        name: "event.target.value",
        pattern: SourceKind::MemberAccess("event.target.value"),
        taint_label: "user_input",
        description: "Form input value - user controlled",
    },
    SourceDef {
        name: "e.target.value",
        pattern: SourceKind::MemberAccess("e.target.value"),
        taint_label: "user_input",
        description: "Form input value - user controlled",
    },
    // Fetch responses
    SourceDef {
        name: "fetch_response",
        pattern: SourceKind::FunctionCall("fetch"),
        taint_label: "external_data",
        description: "Fetch API response - external data",
    },
    // Document
    SourceDef {
        name: "document.referrer",
        pattern: SourceKind::MemberAccess("document.referrer"),
        taint_label: "referrer",
        description: "Document referrer - attacker controlled",
    },
];

/// Dangerous sinks - where tainted data can cause XSS
/// NOTE: These are DETECTION patterns for static analysis
static REACT_SINKS: [SinkDef; 10] = [
    // The main React XSS vector - DETECTION pattern
    SinkDef {
        name: "dangerous_inner_html",
        pattern: SinkKind::PropertyAssignment("dangerouslySetInnerHTML"),
        rule_id: "react/dangerous-html",
        severity: Severity::Critical,
        description: "Detects raw HTML insertion - bypasses React XSS protection",
        cwe: Some("CWE-79"),
    },
    // Direct DOM manipulation (anti-pattern in React)
    SinkDef {
        name: "ref.current.innerHTML",
        pattern: SinkKind::PropertyAssignment("innerHTML"),
        rule_id: "react/ref-innerhtml",
        severity: Severity::Critical,
        description: "Detects innerHTML on ref - bypasses React's virtual DOM",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "ref.current.outerHTML",
        pattern: SinkKind::PropertyAssignment("outerHTML"),
        rule_id: "react/ref-outerhtml",
        severity: Severity::Critical,
        description: "Detects outerHTML on ref - bypasses React's virtual DOM",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "insertAdjacentHTML",
        pattern: SinkKind::MethodCall("insertAdjacentHTML"),
        rule_id: "react/insert-html",
        severity: Severity::Critical,
        description: "Detects insertAdjacentHTML - bypasses React",
        cwe: Some("CWE-79"),
    },
    // Link href with javascript:
    SinkDef {
        name: "href_javascript",
        pattern: SinkKind::PropertyAssignment("href"),
        rule_id: "react/javascript-url",
        severity: Severity::Error,
        description: "Detects href assignment - potential javascript: URL",
        cwe: Some("CWE-79"),
    },
    // Dynamic code execution sinks - DETECTION only
    SinkDef {
        name: "dynamic_code_eval",
        pattern: SinkKind::FunctionCall("eval"),
        rule_id: "react/dynamic-code",
        severity: Severity::Critical,
        description: "Detects dynamic code execution in React component",
        cwe: Some("CWE-94"),
    },
    SinkDef {
        name: "Function_constructor",
        pattern: SinkKind::FunctionCall("Function"),
        rule_id: "react/function-constructor",
        severity: Severity::Critical,
        description: "Detects Function constructor - code injection",
        cwe: Some("CWE-94"),
    },
    // Document write (anti-pattern)
    SinkDef {
        name: "document.write",
        pattern: SinkKind::MethodCall("write"),
        rule_id: "react/document-write",
        severity: Severity::Error,
        description: "Detects document.write - anti-pattern and XSS risk",
        cwe: Some("CWE-79"),
    },
    // Window.open with user URL
    SinkDef {
        name: "window.open",
        pattern: SinkKind::FunctionCall("window.open"),
        rule_id: "react/window-open",
        severity: Severity::Warning,
        description: "Detects window.open with user URL - potential open redirect",
        cwe: Some("CWE-601"),
    },
    // Location assignment
    SinkDef {
        name: "location.href",
        pattern: SinkKind::PropertyAssignment("location.href"),
        rule_id: "react/location-assign",
        severity: Severity::Warning,
        description: "Detects location.href assignment - potential open redirect",
        cwe: Some("CWE-601"),
    },
];

/// Sanitizers - functions that neutralize tainted data
static REACT_SANITIZERS: [SanitizerDef; 8] = [
    SanitizerDef {
        name: "DOMPurify.sanitize",
        pattern: SanitizerKind::Function("DOMPurify.sanitize"),
        sanitizes: "html",
        description: "DOMPurify HTML sanitization - makes HTML safe",
    },
    SanitizerDef {
        name: "sanitize-html",
        pattern: SanitizerKind::Function("sanitizeHtml"),
        sanitizes: "html",
        description: "sanitize-html package for safe HTML",
    },
    SanitizerDef {
        name: "xss",
        pattern: SanitizerKind::Function("xss"),
        sanitizes: "html",
        description: "xss package for HTML filtering",
    },
    SanitizerDef {
        name: "isomorphic-dompurify",
        pattern: SanitizerKind::Function("purify"),
        sanitizes: "html",
        description: "Isomorphic DOMPurify for SSR",
    },
    SanitizerDef {
        name: "escape-html",
        pattern: SanitizerKind::Function("escapeHtml"),
        sanitizes: "html",
        description: "escape-html package for entity encoding",
    },
    SanitizerDef {
        name: "encodeURIComponent",
        pattern: SanitizerKind::Function("encodeURIComponent"),
        sanitizes: "url",
        description: "URL component encoding",
    },
    SanitizerDef {
        name: "jsx_auto_escape",
        pattern: SanitizerKind::TemplateEngine("JSX"),
        sanitizes: "html",
        description: "JSX automatically escapes expressions",
    },
    SanitizerDef {
        name: "createTextNode",
        pattern: SanitizerKind::Function("createTextNode"),
        sanitizes: "html",
        description: "Creates text node - safe from HTML interpretation",
    },
];

/// Safe patterns in React
static REACT_SAFE_PATTERNS: [SafePattern; 6] = [
    SafePattern {
        name: "jsx_expression",
        pattern: "{userInput}",
        reason: "JSX expressions are automatically escaped",
    },
    SafePattern {
        name: "text_content",
        pattern: "<div>{userInput}</div>",
        reason: "Text content in JSX is auto-escaped",
    },
    SafePattern {
        name: "sanitized_html",
        pattern: "__html: DOMPurify.sanitize(html)",
        reason: "DOMPurify sanitizes HTML before insertion",
    },
    SafePattern {
        name: "safe_link",
        pattern: "<Link to={path}>",
        reason: "React Router Link validates paths",
    },
    SafePattern {
        name: "validated_url",
        pattern: "new URL(userInput, window.location.origin)",
        reason: "URL constructor validates and normalizes URLs",
    },
    SafePattern {
        name: "textContent_assignment",
        pattern: "ref.current.textContent = userInput",
        reason: "textContent is safe - treated as text not HTML",
    },
];

/// Dangerous patterns in React - DETECTION patterns for static analysis
static REACT_DANGEROUS_PATTERNS: [DangerousPattern; 8] = [
    DangerousPattern {
        name: "raw_html_prop",
        pattern: PatternKind::Construct("__html: props.content"),
        rule_id: "react/unsanitized-html",
        severity: Severity::Critical,
        description: "Detects unsanitized HTML from props - XSS vulnerability",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "javascript_url",
        pattern: PatternKind::Regex(r#"href\s*=\s*[`'"]\s*javascript:"#),
        rule_id: "react/javascript-url",
        severity: Severity::Critical,
        description: "Detects javascript: URL in href - XSS",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "dynamic_href",
        pattern: PatternKind::Construct("href={userInput}"),
        rule_id: "react/dynamic-href",
        severity: Severity::Warning,
        description: "Detects dynamic href - validate to prevent javascript: URLs",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "dom_manipulation",
        pattern: PatternKind::MethodCall("innerHTML"),
        rule_id: "react/direct-dom",
        severity: Severity::Error,
        description: "Detects direct DOM manipulation - prefer React patterns",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "ref_innerhtml",
        pattern: PatternKind::Construct("ref.current.innerHTML"),
        rule_id: "react/ref-innerhtml",
        severity: Severity::Critical,
        description: "Detects innerHTML on ref - bypasses React protection",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "dynamic_code_in_effect",
        pattern: PatternKind::Construct("useEffect with dynamic code"),
        rule_id: "react/dynamic-effect",
        severity: Severity::Critical,
        description: "Detects dynamic code execution in useEffect - code injection",
        cwe: Some("CWE-94"),
    },
    DangerousPattern {
        name: "unsanitized_markdown",
        pattern: PatternKind::Construct("__html: marked(userContent)"),
        rule_id: "react/markdown-xss",
        severity: Severity::Error,
        description: "Detects unsanitized markdown rendering - sanitize output",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "string_ref",
        pattern: PatternKind::Construct("ref=\"stringRef\""),
        rule_id: "react/string-ref",
        severity: Severity::Warning,
        description: "Detects string refs (deprecated) - use callback or createRef",
        cwe: None,
    },
];

/// React-specific resources
static REACT_RESOURCES: [ResourceType; 3] = [
    ResourceType {
        name: "EventListener",
        acquire_pattern: "addEventListener",
        release_pattern: "removeEventListener",
        leak_consequence: "Memory leak - listener keeps component in memory",
    },
    ResourceType {
        name: "Interval",
        acquire_pattern: "setInterval",
        release_pattern: "clearInterval",
        leak_consequence: "Interval continues after unmount - memory leak",
    },
    ResourceType {
        name: "Timeout",
        acquire_pattern: "setTimeout",
        release_pattern: "clearTimeout",
        leak_consequence: "Callback may run after unmount - state update on unmounted",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_detection() {
        assert!(REACT_PROFILE.is_active("import React from 'react';"));
        assert!(REACT_PROFILE.is_active("import { useState } from 'react';"));
        assert!(REACT_PROFILE.is_active("const React = require('react');"));
        assert!(REACT_PROFILE.is_active("import ReactDOM from 'react-dom';"));
        assert!(!REACT_PROFILE.is_active("import Vue from 'vue';"));
    }

    #[test]
    fn test_sources() {
        assert!(!REACT_SOURCES.is_empty());
        assert!(REACT_SOURCES.iter().any(|s| s.name == "props"));
        assert!(REACT_SOURCES.iter().any(|s| s.name == "useSearchParams"));
    }

    #[test]
    fn test_sinks() {
        assert!(!REACT_SINKS.is_empty());
        assert!(REACT_SINKS.iter().any(|s| s.name == "dangerous_inner_html"));
    }

    #[test]
    fn test_sanitizers() {
        assert!(!REACT_SANITIZERS.is_empty());
        assert!(
            REACT_SANITIZERS
                .iter()
                .any(|s| s.name == "DOMPurify.sanitize")
        );
    }
}
