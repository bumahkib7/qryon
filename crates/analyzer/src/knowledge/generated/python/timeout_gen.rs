//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TIMEOUT_GEN_SOURCES: &[SourceDef] = &[];

static TIMEOUT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "timeout",
    pattern: SinkKind::FunctionCall("timeout"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: timeout (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static TIMEOUT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TIMEOUT_GEN_IMPORTS: &[&str] = &["timeout"];

pub static TIMEOUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "timeout_generated",
    description: "Generated profile for timeout from CodeQL/Pysa",
    detect_imports: TIMEOUT_GEN_IMPORTS,
    sources: TIMEOUT_GEN_SOURCES,
    sinks: TIMEOUT_GEN_SINKS,
    sanitizers: TIMEOUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
