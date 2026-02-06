//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static JSON_GEN_SOURCES: &[SourceDef] = &[];

static JSON_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "json",
    pattern: SinkKind::FunctionCall("json"),
    rule_id: "python/gen-pysa-httpclientrequest_data",
    severity: Severity::Error,
    description: "Pysa sink: json (kind: HTTPClientRequest_DATA)",
    cwe: Some("CWE-74"),
}];

static JSON_GEN_SANITIZERS: &[SanitizerDef] = &[];

static JSON_GEN_IMPORTS: &[&str] = &["json"];

pub static JSON_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "json_generated",
    description: "Generated profile for json from CodeQL/Pysa",
    detect_imports: JSON_GEN_IMPORTS,
    sources: JSON_GEN_SOURCES,
    sinks: JSON_GEN_SINKS,
    sanitizers: JSON_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
