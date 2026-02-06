//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REASON_GEN_SOURCES: &[SourceDef] = &[];

static REASON_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "reason",
    pattern: SinkKind::FunctionCall("reason"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: reason (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static REASON_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REASON_GEN_IMPORTS: &[&str] = &["reason"];

pub static REASON_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "reason_generated",
    description: "Generated profile for reason from CodeQL/Pysa",
    detect_imports: REASON_GEN_IMPORTS,
    sources: REASON_GEN_SOURCES,
    sinks: REASON_GEN_SINKS,
    sanitizers: REASON_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
