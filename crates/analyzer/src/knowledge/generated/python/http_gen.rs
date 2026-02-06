//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HTTP_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "http.client.HTTPConnection.getresponse",
    pattern: SourceKind::MemberAccess("http.client.HTTPConnection.getresponse"),
    taint_label: "user_input",
    description: "Pysa source: http.client.HTTPConnection.getresponse (kind: DataFromInternet)",
}];

static HTTP_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "http.server.BaseHTTPRequestHandler.send_error",
        pattern: SinkKind::FunctionCall("http.server.BaseHTTPRequestHandler.send_error"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: http.server.BaseHTTPRequestHandler.send_error (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "http.server.BaseHTTPRequestHandler.send_response",
        pattern: SinkKind::FunctionCall("http.server.BaseHTTPRequestHandler.send_response"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: http.server.BaseHTTPRequestHandler.send_response (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "http.server.BaseHTTPRequestHandler.send_response_only",
        pattern: SinkKind::FunctionCall("http.server.BaseHTTPRequestHandler.send_response_only"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: http.server.BaseHTTPRequestHandler.send_response_only (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
];

static HTTP_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HTTP_GEN_IMPORTS: &[&str] = &["http"];

pub static HTTP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "http_generated",
    description: "Generated profile for http from CodeQL/Pysa",
    detect_imports: HTTP_GEN_IMPORTS,
    sources: HTTP_GEN_SOURCES,
    sinks: HTTP_GEN_SINKS,
    sanitizers: HTTP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
