//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SOCKETSERVER_GEN_SOURCES: &[SourceDef] = &[];

static SOCKETSERVER_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "socketserver.StreamRequestHandler.wfile",
        pattern: SinkKind::FunctionCall("socketserver.StreamRequestHandler.wfile"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: socketserver.StreamRequestHandler.wfile (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "socketserver.DatagramRequestHandler.wfile",
        pattern: SinkKind::FunctionCall("socketserver.DatagramRequestHandler.wfile"),
        rule_id: "python/gen-pysa-returnedtouser",
        severity: Severity::Error,
        description: "Pysa sink: socketserver.DatagramRequestHandler.wfile (kind: ReturnedToUser)",
        cwe: Some("CWE-74"),
    },
];

static SOCKETSERVER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SOCKETSERVER_GEN_IMPORTS: &[&str] = &["socketserver"];

pub static SOCKETSERVER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "socketserver_generated",
    description: "Generated profile for socketserver from CodeQL/Pysa",
    detect_imports: SOCKETSERVER_GEN_IMPORTS,
    sources: SOCKETSERVER_GEN_SOURCES,
    sinks: SOCKETSERVER_GEN_SINKS,
    sanitizers: SOCKETSERVER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
