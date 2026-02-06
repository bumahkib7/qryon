//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FASTAPI_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "fastapi.Request.cookies",
        pattern: SourceKind::MemberAccess("fastapi.Request.cookies"),
        taint_label: "user_input",
        description: "Pysa source: fastapi.Request.cookies (kind: Cookies)",
    },
    SourceDef {
        name: "fastapi.WebSocket.cookies",
        pattern: SourceKind::MemberAccess("fastapi.WebSocket.cookies"),
        taint_label: "user_input",
        description: "Pysa source: fastapi.WebSocket.cookies (kind: Cookies)",
    },
];

static FASTAPI_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "fastapi.applications.FastAPI.__init__",
        pattern: SinkKind::FunctionCall("fastapi.applications.FastAPI.__init__"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: fastapi.applications.FastAPI.__init__ (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "fastapi.responses.HTMLResponse.body",
        pattern: SinkKind::FunctionCall("fastapi.responses.HTMLResponse.body"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: fastapi.responses.HTMLResponse.body (kind: XSS)",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "fastapi.responses.Response.body",
        pattern: SinkKind::FunctionCall("fastapi.responses.Response.body"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: fastapi.responses.Response.body (kind: XSS)",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "fastapi.responses.RedirectResponse.body",
        pattern: SinkKind::FunctionCall("fastapi.responses.RedirectResponse.body"),
        rule_id: "python/gen-pysa-redirect",
        severity: Severity::Error,
        description: "Pysa sink: fastapi.responses.RedirectResponse.body (kind: Redirect)",
        cwe: Some("CWE-601"),
    },
    SinkDef {
        name: "fastapi.WebSocket.cookies",
        pattern: SinkKind::FunctionCall("fastapi.WebSocket.cookies"),
        rule_id: "python/gen-pysa-cookiewrite",
        severity: Severity::Error,
        description: "Pysa sink: fastapi.WebSocket.cookies (kind: CookieWrite)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "starlette.responses.Response.set_cookie",
        pattern: SinkKind::FunctionCall("starlette.responses.Response.set_cookie"),
        rule_id: "python/gen-pysa-cookiewrite",
        severity: Severity::Error,
        description: "Pysa sink: starlette.responses.Response.set_cookie (kind: CookieWrite)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "starlette.responses.Response.delete_cookie",
        pattern: SinkKind::FunctionCall("starlette.responses.Response.delete_cookie"),
        rule_id: "python/gen-pysa-cookiewrite",
        severity: Severity::Error,
        description: "Pysa sink: starlette.responses.Response.delete_cookie (kind: CookieWrite)",
        cwe: Some("CWE-74"),
    },
];

static FASTAPI_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FASTAPI_GEN_IMPORTS: &[&str] = &["fastapi", "starlette"];

pub static FASTAPI_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "fastapi_generated",
    description: "Generated profile for fastapi from CodeQL/Pysa",
    detect_imports: FASTAPI_GEN_IMPORTS,
    sources: FASTAPI_GEN_SOURCES,
    sinks: FASTAPI_GEN_SINKS,
    sanitizers: FASTAPI_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
