//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static EXTRA_GEN_SOURCES: &[SourceDef] = &[];

static EXTRA_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "extra",
    pattern: SinkKind::FunctionCall("extra"),
    rule_id: "python/gen-pysa-logging",
    severity: Severity::Error,
    description: "Pysa sink: extra (kind: Logging)",
    cwe: Some("CWE-74"),
}];

static EXTRA_GEN_SANITIZERS: &[SanitizerDef] = &[];

static EXTRA_GEN_IMPORTS: &[&str] = &["extra"];

pub static EXTRA_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "extra_generated",
    description: "Generated profile for extra from CodeQL/Pysa",
    detect_imports: EXTRA_GEN_IMPORTS,
    sources: EXTRA_GEN_SOURCES,
    sinks: EXTRA_GEN_SINKS,
    sanitizers: EXTRA_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
