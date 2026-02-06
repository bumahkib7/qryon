//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HEADER_GEN_SOURCES: &[SourceDef] = &[];

static HEADER_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "header",
    pattern: SinkKind::FunctionCall("header"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: header (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static HEADER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HEADER_GEN_IMPORTS: &[&str] = &["header"];

pub static HEADER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "header_generated",
    description: "Generated profile for header from CodeQL/Pysa",
    detect_imports: HEADER_GEN_IMPORTS,
    sources: HEADER_GEN_SOURCES,
    sinks: HEADER_GEN_SINKS,
    sanitizers: HEADER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
