//! Vue.js framework security knowledge
//!
//! Defines taint sources, sinks, and sanitizers for Vue.js applications.
//! Vue has built-in XSS protection through template compilation, but
//! v-html and other patterns can bypass this protection.
//!
//! NOTE: This module DETECTS security vulnerabilities - it does not contain them.
//! The patterns here are used to identify dangerous code during static analysis.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Vue.js framework security profile
pub static VUE_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "vue",
    description: "Vue.js progressive JavaScript framework",
    detect_imports: &[
        "from 'vue'",
        "from \"vue\"",
        "require('vue')",
        "require(\"vue\")",
        "from 'vue-router'",
        "from \"vue-router\"",
        "from '@vue/",
        "import Vue",
        "import { createApp }",
        "import { ref, reactive }",
        "@vue/",
    ],
    sources: &VUE_SOURCES,
    sinks: &VUE_SINKS,
    sanitizers: &VUE_SANITIZERS,
    safe_patterns: &VUE_SAFE_PATTERNS,
    dangerous_patterns: &VUE_DANGEROUS_PATTERNS,
    resource_types: &VUE_RESOURCES,
};

/// Taint sources - where untrusted data enters Vue applications
static VUE_SOURCES: [SourceDef; 18] = [
    // Vue Router (Options API)
    SourceDef {
        name: "this.$route.query",
        pattern: SourceKind::MemberAccess("this.$route.query"),
        taint_label: "url_params",
        description: "URL query parameters - attacker controlled",
    },
    SourceDef {
        name: "this.$route.params",
        pattern: SourceKind::MemberAccess("this.$route.params"),
        taint_label: "route_params",
        description: "Route parameters - attacker controlled",
    },
    SourceDef {
        name: "this.$route.hash",
        pattern: SourceKind::MemberAccess("this.$route.hash"),
        taint_label: "url_hash",
        description: "URL hash - attacker controlled",
    },
    SourceDef {
        name: "this.$route.fullPath",
        pattern: SourceKind::MemberAccess("this.$route.fullPath"),
        taint_label: "url",
        description: "Full URL path - attacker controlled",
    },
    // Vue Router (Composition API)
    SourceDef {
        name: "useRoute().query",
        pattern: SourceKind::FunctionCall("useRoute"),
        taint_label: "url_params",
        description: "Route query via composition API - attacker controlled",
    },
    SourceDef {
        name: "route.query",
        pattern: SourceKind::MemberAccess("route.query"),
        taint_label: "url_params",
        description: "Route query params - attacker controlled",
    },
    SourceDef {
        name: "route.params",
        pattern: SourceKind::MemberAccess("route.params"),
        taint_label: "route_params",
        description: "Route params - attacker controlled",
    },
    // Props and attributes
    SourceDef {
        name: "props",
        pattern: SourceKind::MemberAccess("props"),
        taint_label: "component_props",
        description: "Component props - may contain user data",
    },
    SourceDef {
        name: "this.$attrs",
        pattern: SourceKind::MemberAccess("this.$attrs"),
        taint_label: "attributes",
        description: "Fall-through attributes - may contain user data",
    },
    SourceDef {
        name: "$attrs",
        pattern: SourceKind::MemberAccess("$attrs"),
        taint_label: "attributes",
        description: "Fall-through attributes in template",
    },
    // Slots
    SourceDef {
        name: "this.$slots",
        pattern: SourceKind::MemberAccess("this.$slots"),
        taint_label: "slot_content",
        description: "Slot content - may contain user-provided content",
    },
    // Browser APIs
    SourceDef {
        name: "window.location",
        pattern: SourceKind::MemberAccess("window.location"),
        taint_label: "url_data",
        description: "Browser location - attacker controlled",
    },
    SourceDef {
        name: "location.search",
        pattern: SourceKind::MemberAccess("location.search"),
        taint_label: "query_string",
        description: "URL query string - attacker controlled",
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
    // Fetch
    SourceDef {
        name: "fetch_response",
        pattern: SourceKind::FunctionCall("fetch"),
        taint_label: "external_data",
        description: "Fetch API response - external data",
    },
    // Axios
    SourceDef {
        name: "axios_response",
        pattern: SourceKind::FunctionCall("axios"),
        taint_label: "external_data",
        description: "Axios response - external data",
    },
];

/// Dangerous sinks in Vue
static VUE_SINKS: [SinkDef; 10] = [
    // v-html directive - the main XSS vector in Vue
    SinkDef {
        name: "v-html",
        pattern: SinkKind::PropertyAssignment("v-html"),
        rule_id: "vue/v-html-xss",
        severity: Severity::Critical,
        description: "Detects v-html directive - bypasses Vue template XSS protection",
        cwe: Some("CWE-79"),
    },
    // innerHTML (direct DOM manipulation)
    SinkDef {
        name: "innerHTML",
        pattern: SinkKind::PropertyAssignment("innerHTML"),
        rule_id: "vue/innerhtml-xss",
        severity: Severity::Critical,
        description: "Detects innerHTML assignment - direct DOM XSS",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "outerHTML",
        pattern: SinkKind::PropertyAssignment("outerHTML"),
        rule_id: "vue/outerhtml-xss",
        severity: Severity::Critical,
        description: "Detects outerHTML assignment - direct DOM XSS",
        cwe: Some("CWE-79"),
    },
    // Dynamic component with user input
    SinkDef {
        name: "component_is",
        pattern: SinkKind::PropertyAssignment(":is"),
        rule_id: "vue/dynamic-component",
        severity: Severity::Warning,
        description: "Detects dynamic component - validate component name",
        cwe: Some("CWE-94"),
    },
    // Router navigation
    SinkDef {
        name: "router.push",
        pattern: SinkKind::MethodCall("push"),
        rule_id: "vue/open-redirect",
        severity: Severity::Warning,
        description: "Detects router navigation - potential open redirect",
        cwe: Some("CWE-601"),
    },
    SinkDef {
        name: "router.replace",
        pattern: SinkKind::MethodCall("replace"),
        rule_id: "vue/open-redirect",
        severity: Severity::Warning,
        description: "Detects router replace - potential open redirect",
        cwe: Some("CWE-601"),
    },
    // Location assignment
    SinkDef {
        name: "window.location",
        pattern: SinkKind::PropertyAssignment("window.location"),
        rule_id: "vue/location-assign",
        severity: Severity::Warning,
        description: "Detects location assignment - potential open redirect",
        cwe: Some("CWE-601"),
    },
    // Dynamic code
    SinkDef {
        name: "dynamic_code_eval",
        pattern: SinkKind::FunctionCall("eval"),
        rule_id: "vue/dynamic-code",
        severity: Severity::Critical,
        description: "Detects dynamic code execution - code injection",
        cwe: Some("CWE-94"),
    },
    // compile function
    SinkDef {
        name: "Vue.compile",
        pattern: SinkKind::FunctionCall("compile"),
        rule_id: "vue/template-injection",
        severity: Severity::Critical,
        description: "Detects runtime template compilation - template injection",
        cwe: Some("CWE-94"),
    },
    // createApp with template
    SinkDef {
        name: "createApp_template",
        pattern: SinkKind::FunctionCall("createApp"),
        rule_id: "vue/template-injection",
        severity: Severity::Warning,
        description: "Detects createApp with dynamic template - verify template source",
        cwe: Some("CWE-94"),
    },
];

/// Sanitizers in Vue
static VUE_SANITIZERS: [SanitizerDef; 8] = [
    SanitizerDef {
        name: "DOMPurify.sanitize",
        pattern: SanitizerKind::Function("DOMPurify.sanitize"),
        sanitizes: "html",
        description: "DOMPurify HTML sanitization - safe for v-html",
    },
    SanitizerDef {
        name: "sanitize-html",
        pattern: SanitizerKind::Function("sanitizeHtml"),
        sanitizes: "html",
        description: "sanitize-html package",
    },
    SanitizerDef {
        name: "xss",
        pattern: SanitizerKind::Function("xss"),
        sanitizes: "html",
        description: "xss package for HTML filtering",
    },
    // Vue template auto-escaping
    SanitizerDef {
        name: "vue_template",
        pattern: SanitizerKind::TemplateEngine("vue-template"),
        sanitizes: "html",
        description: "Vue template auto-escapes {{ }} expressions",
    },
    SanitizerDef {
        name: "v-text",
        pattern: SanitizerKind::Function("v-text"),
        sanitizes: "html",
        description: "v-text directive escapes content",
    },
    // Encoding
    SanitizerDef {
        name: "encodeURIComponent",
        pattern: SanitizerKind::Function("encodeURIComponent"),
        sanitizes: "url",
        description: "URL component encoding",
    },
    SanitizerDef {
        name: "parseInt",
        pattern: SanitizerKind::Function("parseInt"),
        sanitizes: "numeric",
        description: "Convert to integer",
    },
    SanitizerDef {
        name: "Number",
        pattern: SanitizerKind::Function("Number"),
        sanitizes: "numeric",
        description: "Convert to number",
    },
];

/// Safe patterns in Vue
static VUE_SAFE_PATTERNS: [SafePattern; 6] = [
    SafePattern {
        name: "template_interpolation",
        pattern: "{{ userInput }}",
        reason: "Vue template interpolation auto-escapes content",
    },
    SafePattern {
        name: "v_text",
        pattern: "v-text=\"userInput\"",
        reason: "v-text directive escapes content as text",
    },
    SafePattern {
        name: "sanitized_v_html",
        pattern: "v-html=\"DOMPurify.sanitize(html)\"",
        reason: "DOMPurify sanitizes HTML before rendering",
    },
    SafePattern {
        name: "router_link",
        pattern: "<router-link :to=\"path\">",
        reason: "router-link validates routes",
    },
    SafePattern {
        name: "v_bind_class",
        pattern: ":class=\"className\"",
        reason: "Class binding doesn't execute code",
    },
    SafePattern {
        name: "v_bind_style",
        pattern: ":style=\"styleObject\"",
        reason: "Style binding with object is safe",
    },
];

/// Dangerous patterns in Vue
static VUE_DANGEROUS_PATTERNS: [DangerousPattern; 8] = [
    DangerousPattern {
        name: "v_html_props",
        pattern: PatternKind::Construct("v-html=\"props.content\""),
        rule_id: "vue/unsanitized-html",
        severity: Severity::Critical,
        description: "Detects unsanitized prop content in v-html - XSS",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "v_html_user_data",
        pattern: PatternKind::Regex(r#"v-html\s*=\s*["'][^"']*\.(query|params|body)"#),
        rule_id: "vue/user-data-html",
        severity: Severity::Critical,
        description: "Detects user data in v-html - XSS",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "dynamic_component_user",
        pattern: PatternKind::Construct(":is=\"userComponent\""),
        rule_id: "vue/dynamic-component",
        severity: Severity::Error,
        description: "Detects dynamic component with user input - validate component name",
        cwe: Some("CWE-94"),
    },
    DangerousPattern {
        name: "runtime_compilation",
        pattern: PatternKind::Construct("Vue.compile(userTemplate)"),
        rule_id: "vue/template-injection",
        severity: Severity::Critical,
        description: "Detects runtime template compilation with user input - template injection",
        cwe: Some("CWE-94"),
    },
    DangerousPattern {
        name: "unvalidated_redirect",
        pattern: PatternKind::Construct("router.push(userUrl)"),
        rule_id: "vue/open-redirect",
        severity: Severity::Error,
        description: "Detects unvalidated router navigation - open redirect",
        cwe: Some("CWE-601"),
    },
    DangerousPattern {
        name: "v_on_handler_string",
        pattern: PatternKind::Construct("@click=\"dynamicHandler\""),
        rule_id: "vue/dynamic-handler",
        severity: Severity::Warning,
        description: "Detects dynamic event handler - verify handler source",
        cwe: None,
    },
    DangerousPattern {
        name: "style_injection",
        pattern: PatternKind::Construct(":style=\"userStyle\""),
        rule_id: "vue/style-injection",
        severity: Severity::Warning,
        description: "Detects dynamic style with user input - potential CSS injection",
        cwe: None,
    },
    DangerousPattern {
        name: "exposed_secrets",
        pattern: PatternKind::Regex(r#"(VUE_APP_|VITE_)[A-Z_]*SECRET"#),
        rule_id: "vue/env-exposure",
        severity: Severity::Warning,
        description: "Detects potentially exposed secrets in env vars",
        cwe: Some("CWE-200"),
    },
];

/// Vue-specific resources
static VUE_RESOURCES: [ResourceType; 3] = [
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
        leak_consequence: "Interval continues after unmount",
    },
    ResourceType {
        name: "Watcher",
        acquire_pattern: "watch() / $watch",
        release_pattern: "stop() / unwatch",
        leak_consequence: "Watcher continues to run",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_detection() {
        assert!(VUE_PROFILE.is_active("import Vue from 'vue';"));
        assert!(VUE_PROFILE.is_active("import { createApp } from 'vue';"));
        assert!(VUE_PROFILE.is_active("import { ref, reactive } from 'vue';"));
        assert!(VUE_PROFILE.is_active("import { useRouter } from 'vue-router';"));
        assert!(!VUE_PROFILE.is_active("import React from 'react';"));
    }

    #[test]
    fn test_sources() {
        assert!(!VUE_SOURCES.is_empty());
        assert!(VUE_SOURCES.iter().any(|s| s.name == "this.$route.query"));
        assert!(VUE_SOURCES.iter().any(|s| s.name == "route.params"));
    }

    #[test]
    fn test_sinks() {
        assert!(!VUE_SINKS.is_empty());
        assert!(VUE_SINKS.iter().any(|s| s.name == "v-html"));
        assert!(VUE_SINKS.iter().any(|s| s.name == "Vue.compile"));
    }

    #[test]
    fn test_sanitizers() {
        assert!(!VUE_SANITIZERS.is_empty());
        assert!(VUE_SANITIZERS.iter().any(|s| s.name == "vue_template"));
    }
}
