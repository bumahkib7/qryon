//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORS_GEN_SOURCES: &[SourceDef] = &[];

static CORS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "cors.Argument[0].Member[origin]",
    pattern: SinkKind::FunctionCall("origin"),
    rule_id: "javascript/gen-cors-origin",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0].Member[origin] (kind: cors-origin)",
    cwe: Some("CWE-74"),
}];

static CORS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORS_GEN_IMPORTS: &[&str] = &["cors"];

pub static CORS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "cors_generated",
    description: "Generated profile for cors from CodeQL/Pysa",
    detect_imports: CORS_GEN_IMPORTS,
    sources: CORS_GEN_SOURCES,
    sinks: CORS_GEN_SINKS,
    sanitizers: CORS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
