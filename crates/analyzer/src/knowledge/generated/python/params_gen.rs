//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PARAMS_GEN_SOURCES: &[SourceDef] = &[];

static PARAMS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "params",
    pattern: SinkKind::FunctionCall("params"),
    rule_id: "python/gen-pysa-httpclientrequest_data",
    severity: Severity::Error,
    description: "Pysa sink: params (kind: HTTPClientRequest_DATA)",
    cwe: Some("CWE-74"),
}];

static PARAMS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PARAMS_GEN_IMPORTS: &[&str] = &["params"];

pub static PARAMS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "params_generated",
    description: "Generated profile for params from CodeQL/Pysa",
    detect_imports: PARAMS_GEN_IMPORTS,
    sources: PARAMS_GEN_SOURCES,
    sinks: PARAMS_GEN_SINKS,
    sanitizers: PARAMS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
