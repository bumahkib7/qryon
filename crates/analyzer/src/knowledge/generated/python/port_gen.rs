//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PORT_GEN_SOURCES: &[SourceDef] = &[];

static PORT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "port",
    pattern: SinkKind::FunctionCall("port"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: port (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static PORT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PORT_GEN_IMPORTS: &[&str] = &["port"];

pub static PORT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "port_generated",
    description: "Generated profile for port from CodeQL/Pysa",
    detect_imports: PORT_GEN_IMPORTS,
    sources: PORT_GEN_SOURCES,
    sinks: PORT_GEN_SINKS,
    sanitizers: PORT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
