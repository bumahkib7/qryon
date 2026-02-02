//! Next.js framework security knowledge
//!
//! Defines taint sources, sinks, and sanitizers for Next.js applications.
//! Next.js adds server-side rendering and API routes to React, introducing
//! additional attack surfaces.
//!
//! NOTE: This module DETECTS security vulnerabilities - it does not contain them.
//! The patterns here are used to identify dangerous code during static analysis.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Next.js framework security profile
pub static NEXTJS_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "nextjs",
    description: "Next.js React framework with SSR and API routes",
    detect_imports: &[
        "from 'next'",
        "from \"next\"",
        "from 'next/router'",
        "from 'next/navigation'",
        "from 'next/link'",
        "from 'next/image'",
        "from 'next/head'",
        "from 'next/script'",
        "from 'next/server'",
        "from 'next/headers'",
        "from '@next/font'",
        "import { NextResponse }",
        "import { NextRequest }",
        "next/",
        "@next/",
    ],
    sources: &NEXTJS_SOURCES,
    sinks: &NEXTJS_SINKS,
    sanitizers: &NEXTJS_SANITIZERS,
    safe_patterns: &NEXTJS_SAFE_PATTERNS,
    dangerous_patterns: &NEXTJS_DANGEROUS_PATTERNS,
    resource_types: &NEXTJS_RESOURCES,
};

/// Taint sources - where untrusted data enters Next.js applications
static NEXTJS_SOURCES: [SourceDef; 22] = [
    // Pages Router - getServerSideProps/getStaticProps context
    SourceDef {
        name: "context.query",
        pattern: SourceKind::MemberAccess("context.query"),
        taint_label: "url_params",
        description: "URL query parameters in SSR context - attacker controlled",
    },
    SourceDef {
        name: "context.params",
        pattern: SourceKind::MemberAccess("context.params"),
        taint_label: "route_params",
        description: "Dynamic route parameters - attacker controlled",
    },
    SourceDef {
        name: "ctx.query",
        pattern: SourceKind::MemberAccess("ctx.query"),
        taint_label: "url_params",
        description: "Query params in _app context - attacker controlled",
    },
    SourceDef {
        name: "req.query",
        pattern: SourceKind::MemberAccess("req.query"),
        taint_label: "url_params",
        description: "API route query parameters - attacker controlled",
    },
    SourceDef {
        name: "req.body",
        pattern: SourceKind::MemberAccess("req.body"),
        taint_label: "request_body",
        description: "API route request body - attacker controlled",
    },
    SourceDef {
        name: "req.cookies",
        pattern: SourceKind::MemberAccess("req.cookies"),
        taint_label: "cookies",
        description: "Request cookies - attacker controlled",
    },
    SourceDef {
        name: "req.headers",
        pattern: SourceKind::MemberAccess("req.headers"),
        taint_label: "http_headers",
        description: "Request headers - attacker controlled",
    },
    // App Router sources
    SourceDef {
        name: "searchParams",
        pattern: SourceKind::MemberAccess("searchParams"),
        taint_label: "url_params",
        description: "App Router search params - attacker controlled",
    },
    SourceDef {
        name: "params",
        pattern: SourceKind::MemberAccess("params"),
        taint_label: "route_params",
        description: "App Router dynamic params - attacker controlled",
    },
    SourceDef {
        name: "headers()",
        pattern: SourceKind::FunctionCall("headers"),
        taint_label: "http_headers",
        description: "Next.js headers() function - attacker controlled",
    },
    SourceDef {
        name: "cookies()",
        pattern: SourceKind::FunctionCall("cookies"),
        taint_label: "cookies",
        description: "Next.js cookies() function - attacker controlled",
    },
    // NextRequest methods
    SourceDef {
        name: "request.nextUrl",
        pattern: SourceKind::MemberAccess("request.nextUrl"),
        taint_label: "url_data",
        description: "NextRequest URL object - attacker controlled",
    },
    SourceDef {
        name: "request.nextUrl.searchParams",
        pattern: SourceKind::MemberAccess("nextUrl.searchParams"),
        taint_label: "url_params",
        description: "NextRequest search params - attacker controlled",
    },
    SourceDef {
        name: "request.headers",
        pattern: SourceKind::MethodOnType {
            type_pattern: "NextRequest",
            method: "headers",
        },
        taint_label: "http_headers",
        description: "NextRequest headers - attacker controlled",
    },
    SourceDef {
        name: "request.cookies",
        pattern: SourceKind::MethodOnType {
            type_pattern: "NextRequest",
            method: "cookies",
        },
        taint_label: "cookies",
        description: "NextRequest cookies - attacker controlled",
    },
    // Client-side hooks
    SourceDef {
        name: "useSearchParams",
        pattern: SourceKind::FunctionCall("useSearchParams"),
        taint_label: "url_params",
        description: "Client-side search params hook - attacker controlled",
    },
    SourceDef {
        name: "useParams",
        pattern: SourceKind::FunctionCall("useParams"),
        taint_label: "route_params",
        description: "Client-side route params hook - attacker controlled",
    },
    SourceDef {
        name: "usePathname",
        pattern: SourceKind::FunctionCall("usePathname"),
        taint_label: "url_path",
        description: "Current pathname - attacker controlled",
    },
    SourceDef {
        name: "router.query",
        pattern: SourceKind::MemberAccess("router.query"),
        taint_label: "url_params",
        description: "useRouter query params - attacker controlled",
    },
    // Form data
    SourceDef {
        name: "formData",
        pattern: SourceKind::FunctionCall("formData"),
        taint_label: "form_data",
        description: "Server action form data - user controlled",
    },
    // External data
    SourceDef {
        name: "fetch_response",
        pattern: SourceKind::FunctionCall("fetch"),
        taint_label: "external_data",
        description: "Fetch response in SSR - external data",
    },
    // Props from getServerSideProps
    SourceDef {
        name: "props",
        pattern: SourceKind::MemberAccess("props"),
        taint_label: "component_props",
        description: "Page props - may contain user data",
    },
];

/// Dangerous sinks in Next.js
static NEXTJS_SINKS: [SinkDef; 12] = [
    // React XSS sinks (inherited)
    SinkDef {
        name: "dangerous_inner_html",
        pattern: SinkKind::PropertyAssignment("__html"),
        rule_id: "nextjs/dangerous-html",
        severity: Severity::Critical,
        description: "Detects raw HTML insertion - bypasses React XSS protection",
        cwe: Some("CWE-79"),
    },
    // Redirects - potential open redirect
    SinkDef {
        name: "redirect",
        pattern: SinkKind::FunctionCall("redirect"),
        rule_id: "nextjs/open-redirect",
        severity: Severity::Error,
        description: "Detects redirect function - potential open redirect",
        cwe: Some("CWE-601"),
    },
    SinkDef {
        name: "NextResponse.redirect",
        pattern: SinkKind::FunctionCall("NextResponse.redirect"),
        rule_id: "nextjs/open-redirect",
        severity: Severity::Error,
        description: "Detects NextResponse redirect - potential open redirect",
        cwe: Some("CWE-601"),
    },
    SinkDef {
        name: "router.push",
        pattern: SinkKind::MethodCall("push"),
        rule_id: "nextjs/client-redirect",
        severity: Severity::Warning,
        description: "Detects client-side navigation - validate URL",
        cwe: Some("CWE-601"),
    },
    SinkDef {
        name: "router.replace",
        pattern: SinkKind::MethodCall("replace"),
        rule_id: "nextjs/client-redirect",
        severity: Severity::Warning,
        description: "Detects client-side navigation - validate URL",
        cwe: Some("CWE-601"),
    },
    // Response construction
    SinkDef {
        name: "NextResponse.json",
        pattern: SinkKind::FunctionCall("NextResponse.json"),
        rule_id: "nextjs/response-data",
        severity: Severity::Info,
        description: "Detects JSON response - check for sensitive data leakage",
        cwe: None,
    },
    SinkDef {
        name: "res.json",
        pattern: SinkKind::MethodCall("json"),
        rule_id: "nextjs/api-response",
        severity: Severity::Info,
        description: "Detects API response - check for sensitive data leakage",
        cwe: None,
    },
    SinkDef {
        name: "res.send",
        pattern: SinkKind::MethodCall("send"),
        rule_id: "nextjs/api-xss",
        severity: Severity::Warning,
        description: "Detects API text response - potential XSS if HTML",
        cwe: Some("CWE-79"),
    },
    // Headers
    SinkDef {
        name: "res.setHeader",
        pattern: SinkKind::MethodCall("setHeader"),
        rule_id: "nextjs/header-injection",
        severity: Severity::Warning,
        description: "Detects header setting - potential header injection",
        cwe: Some("CWE-113"),
    },
    // Cookies
    SinkDef {
        name: "cookies().set",
        pattern: SinkKind::MethodCall("set"),
        rule_id: "nextjs/cookie-setting",
        severity: Severity::Info,
        description: "Detects cookie setting - verify security flags",
        cwe: None,
    },
    // Dynamic code
    SinkDef {
        name: "dynamic_code_eval",
        pattern: SinkKind::FunctionCall("eval"),
        rule_id: "nextjs/dynamic-code",
        severity: Severity::Critical,
        description: "Detects dynamic code execution - code injection",
        cwe: Some("CWE-94"),
    },
    // revalidatePath/revalidateTag with user input
    SinkDef {
        name: "revalidatePath",
        pattern: SinkKind::FunctionCall("revalidatePath"),
        rule_id: "nextjs/cache-poisoning",
        severity: Severity::Warning,
        description: "Detects cache revalidation - validate path to prevent cache poisoning",
        cwe: None,
    },
];

/// Sanitizers in Next.js
static NEXTJS_SANITIZERS: [SanitizerDef; 10] = [
    SanitizerDef {
        name: "DOMPurify.sanitize",
        pattern: SanitizerKind::Function("DOMPurify.sanitize"),
        sanitizes: "html",
        description: "DOMPurify HTML sanitization",
    },
    SanitizerDef {
        name: "sanitize-html",
        pattern: SanitizerKind::Function("sanitizeHtml"),
        sanitizes: "html",
        description: "sanitize-html package",
    },
    // Zod validation
    SanitizerDef {
        name: "zod.parse",
        pattern: SanitizerKind::Function("parse"),
        sanitizes: "schema",
        description: "Zod schema parsing validates and types data",
    },
    SanitizerDef {
        name: "zod.safeParse",
        pattern: SanitizerKind::Function("safeParse"),
        sanitizes: "schema",
        description: "Zod safe parsing with error handling",
    },
    // Type coercion
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
    // URL validation
    SanitizerDef {
        name: "URL_constructor",
        pattern: SanitizerKind::Function("new URL"),
        sanitizes: "url",
        description: "URL constructor validates URL format",
    },
    SanitizerDef {
        name: "encodeURIComponent",
        pattern: SanitizerKind::Function("encodeURIComponent"),
        sanitizes: "url",
        description: "URL component encoding",
    },
    // JSX auto-escape
    SanitizerDef {
        name: "jsx_auto_escape",
        pattern: SanitizerKind::TemplateEngine("JSX"),
        sanitizes: "html",
        description: "JSX automatically escapes expressions",
    },
    // Yup validation
    SanitizerDef {
        name: "yup.validate",
        pattern: SanitizerKind::Function("validate"),
        sanitizes: "schema",
        description: "Yup schema validation",
    },
];

/// Safe patterns in Next.js
static NEXTJS_SAFE_PATTERNS: [SafePattern; 7] = [
    SafePattern {
        name: "validated_schema",
        pattern: "const data = schema.parse(input)",
        reason: "Zod parsing validates and types input data",
    },
    SafePattern {
        name: "internal_redirect",
        pattern: "redirect('/internal/path')",
        reason: "Hardcoded internal paths are safe",
    },
    SafePattern {
        name: "static_props",
        pattern: "getStaticProps",
        reason: "Static generation runs at build time only",
    },
    SafePattern {
        name: "jsx_expression",
        pattern: "{userInput}",
        reason: "JSX auto-escapes content",
    },
    SafePattern {
        name: "next_link",
        pattern: "<Link href={path}>",
        reason: "Next.js Link validates href internally",
    },
    SafePattern {
        name: "typed_route",
        pattern: "import { redirect } from 'next/navigation'",
        reason: "App router redirect with typed routes",
    },
    SafePattern {
        name: "server_action_binding",
        pattern: "bind(null, id)",
        reason: "Server action binding is type-safe",
    },
];

/// Dangerous patterns in Next.js
static NEXTJS_DANGEROUS_PATTERNS: [DangerousPattern; 9] = [
    DangerousPattern {
        name: "user_redirect",
        pattern: PatternKind::Construct("redirect(userInput)"),
        rule_id: "nextjs/open-redirect",
        severity: Severity::Error,
        description: "Detects redirect with user input - open redirect",
        cwe: Some("CWE-601"),
    },
    DangerousPattern {
        name: "raw_html_ssr",
        pattern: PatternKind::Construct("__html: serverData"),
        rule_id: "nextjs/ssr-xss",
        severity: Severity::Critical,
        description: "Detects unsanitized HTML in SSR - XSS",
        cwe: Some("CWE-79"),
    },
    DangerousPattern {
        name: "exposed_env",
        pattern: PatternKind::Construct("process.env.SECRET"),
        rule_id: "nextjs/env-exposure",
        severity: Severity::Error,
        description: "Detects server env in client - use NEXT_PUBLIC_ prefix for public vars",
        cwe: Some("CWE-200"),
    },
    DangerousPattern {
        name: "dynamic_import_user",
        pattern: PatternKind::Construct("dynamic(() => import(userPath))"),
        rule_id: "nextjs/dynamic-import",
        severity: Severity::Critical,
        description: "Detects dynamic import with user path - code injection",
        cwe: Some("CWE-94"),
    },
    DangerousPattern {
        name: "unsafe_headers",
        pattern: PatternKind::Construct("headers().get(name)"),
        rule_id: "nextjs/header-access",
        severity: Severity::Info,
        description: "Detects header access - validate before use",
        cwe: None,
    },
    DangerousPattern {
        name: "unvalidated_revalidate",
        pattern: PatternKind::Construct("revalidatePath(userPath)"),
        rule_id: "nextjs/cache-poisoning",
        severity: Severity::Warning,
        description: "Detects cache revalidation with user input",
        cwe: None,
    },
    DangerousPattern {
        name: "exposed_api_key",
        pattern: PatternKind::Regex(r#"(api[_-]?key|secret|password)\s*[:=]\s*['"]\w+"#),
        rule_id: "nextjs/hardcoded-secret",
        severity: Severity::Critical,
        description: "Detects hardcoded secrets in code",
        cwe: Some("CWE-798"),
    },
    DangerousPattern {
        name: "cors_wildcard",
        pattern: PatternKind::Construct("Access-Control-Allow-Origin: *"),
        rule_id: "nextjs/cors-wildcard",
        severity: Severity::Warning,
        description: "Detects wildcard CORS - may expose sensitive data",
        cwe: Some("CWE-942"),
    },
    DangerousPattern {
        name: "api_route_sql",
        pattern: PatternKind::Regex(r#"query\s*\(\s*`[^`]*\$\{"#),
        rule_id: "nextjs/sql-injection",
        severity: Severity::Critical,
        description: "Detects SQL query with template literal interpolation",
        cwe: Some("CWE-89"),
    },
];

/// Next.js specific resources
static NEXTJS_RESOURCES: [ResourceType; 2] = [
    ResourceType {
        name: "DatabaseConnection",
        acquire_pattern: "prisma.$connect",
        release_pattern: "prisma.$disconnect",
        leak_consequence: "Connection pool exhaustion in serverless",
    },
    ResourceType {
        name: "FetchCache",
        acquire_pattern: "fetch with cache",
        release_pattern: "revalidatePath/revalidateTag",
        leak_consequence: "Stale data served to users",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_detection() {
        assert!(NEXTJS_PROFILE.is_active("import { useRouter } from 'next/router';"));
        assert!(NEXTJS_PROFILE.is_active("import Head from 'next/head';"));
        assert!(NEXTJS_PROFILE.is_active("import { NextResponse } from 'next/server';"));
        assert!(NEXTJS_PROFILE.is_active("import { headers, cookies } from 'next/headers';"));
        assert!(!NEXTJS_PROFILE.is_active("import express from 'express';"));
    }

    #[test]
    fn test_sources() {
        assert!(!NEXTJS_SOURCES.is_empty());
        assert!(NEXTJS_SOURCES.iter().any(|s| s.name == "context.query"));
        assert!(NEXTJS_SOURCES.iter().any(|s| s.name == "searchParams"));
        assert!(NEXTJS_SOURCES.iter().any(|s| s.name == "headers()"));
    }

    #[test]
    fn test_sinks() {
        assert!(!NEXTJS_SINKS.is_empty());
        assert!(NEXTJS_SINKS.iter().any(|s| s.name == "redirect"));
        assert!(
            NEXTJS_SINKS
                .iter()
                .any(|s| s.name == "NextResponse.redirect")
        );
    }

    #[test]
    fn test_sanitizers() {
        assert!(!NEXTJS_SANITIZERS.is_empty());
        assert!(NEXTJS_SANITIZERS.iter().any(|s| s.name == "zod.parse"));
    }
}
