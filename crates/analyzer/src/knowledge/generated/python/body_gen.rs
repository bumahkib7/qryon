//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static BODY_GEN_SOURCES: &[SourceDef] = &[];

static BODY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "body",
    pattern: SinkKind::FunctionCall("body"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: body (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static BODY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static BODY_GEN_IMPORTS: &[&str] = &["body"];

pub static BODY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "body_generated",
    description: "Generated profile for body from CodeQL/Pysa",
    detect_imports: BODY_GEN_IMPORTS,
    sources: BODY_GEN_SOURCES,
    sinks: BODY_GEN_SINKS,
    sanitizers: BODY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
