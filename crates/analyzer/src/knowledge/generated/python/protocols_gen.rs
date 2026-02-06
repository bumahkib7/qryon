//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PROTOCOLS_GEN_SOURCES: &[SourceDef] = &[];

static PROTOCOLS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "protocols",
    pattern: SinkKind::FunctionCall("protocols"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: protocols (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static PROTOCOLS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PROTOCOLS_GEN_IMPORTS: &[&str] = &["protocols"];

pub static PROTOCOLS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "protocols_generated",
    description: "Generated profile for protocols from CodeQL/Pysa",
    detect_imports: PROTOCOLS_GEN_IMPORTS,
    sources: PROTOCOLS_GEN_SOURCES,
    sinks: PROTOCOLS_GEN_SINKS,
    sanitizers: PROTOCOLS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
