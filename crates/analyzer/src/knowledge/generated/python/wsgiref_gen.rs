//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static WSGIREF_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "wsgiref.handlers.BaseHandler.error_output",
    pattern: SourceKind::MemberAccess("wsgiref.handlers.BaseHandler.error_output"),
    taint_label: "user_input",
    description: "Pysa source: wsgiref.handlers.BaseHandler.error_output (kind: ResponseData)",
}];

static WSGIREF_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "wsgiref.headers.Headers.__setitem__",
        pattern: SinkKind::FunctionCall("wsgiref.headers.Headers.__setitem__"),
        rule_id: "python/gen-pysa-responseheadername",
        severity: Severity::Error,
        description: "Pysa sink: wsgiref.headers.Headers.__setitem__ (kind: ResponseHeaderName)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "wsgiref.headers.Headers.setdefault",
        pattern: SinkKind::FunctionCall("wsgiref.headers.Headers.setdefault"),
        rule_id: "python/gen-pysa-responseheadername",
        severity: Severity::Error,
        description: "Pysa sink: wsgiref.headers.Headers.setdefault (kind: ResponseHeaderName)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "wsgiref.headers.Headers.add_header",
        pattern: SinkKind::FunctionCall("wsgiref.headers.Headers.add_header"),
        rule_id: "python/gen-pysa-responseheadername",
        severity: Severity::Error,
        description: "Pysa sink: wsgiref.headers.Headers.add_header (kind: ResponseHeaderName)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "wsgiref.handlers.BaseHandler.error_body",
        pattern: SinkKind::FunctionCall("wsgiref.handlers.BaseHandler.error_body"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: wsgiref.handlers.BaseHandler.error_body (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "wsgiref.handlers.BaseHandler.write",
        pattern: SinkKind::FunctionCall("wsgiref.handlers.BaseHandler.write"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: wsgiref.handlers.BaseHandler.write (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "wsgiref.handlers.BaseHandler.log_exception",
        pattern: SinkKind::FunctionCall("wsgiref.handlers.BaseHandler.log_exception"),
        rule_id: "python/gen-pysa-logging",
        severity: Severity::Error,
        description: "Pysa sink: wsgiref.handlers.BaseHandler.log_exception (kind: Logging)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "wsgiref.handlers.SimpleHandler.stdout",
        pattern: SinkKind::FunctionCall("wsgiref.handlers.SimpleHandler.stdout"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: wsgiref.handlers.SimpleHandler.stdout (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "wsgiref.handlers.SimpleHandler._write",
        pattern: SinkKind::FunctionCall("wsgiref.handlers.SimpleHandler._write"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: wsgiref.handlers.SimpleHandler._write (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
];

static WSGIREF_GEN_SANITIZERS: &[SanitizerDef] = &[];

static WSGIREF_GEN_IMPORTS: &[&str] = &["wsgiref"];

pub static WSGIREF_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "wsgiref_generated",
    description: "Generated profile for wsgiref from CodeQL/Pysa",
    detect_imports: WSGIREF_GEN_IMPORTS,
    sources: WSGIREF_GEN_SOURCES,
    sinks: WSGIREF_GEN_SINKS,
    sanitizers: WSGIREF_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
