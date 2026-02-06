//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ORIGIN_GEN_SOURCES: &[SourceDef] = &[];

static ORIGIN_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "origin",
    pattern: SinkKind::FunctionCall("origin"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: origin (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static ORIGIN_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ORIGIN_GEN_IMPORTS: &[&str] = &["origin"];

pub static ORIGIN_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "origin_generated",
    description: "Generated profile for origin from CodeQL/Pysa",
    detect_imports: ORIGIN_GEN_IMPORTS,
    sources: ORIGIN_GEN_SOURCES,
    sinks: ORIGIN_GEN_SINKS,
    sanitizers: ORIGIN_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
