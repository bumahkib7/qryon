//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STACK_INFO_GEN_SOURCES: &[SourceDef] = &[];

static STACK_INFO_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "stack_info",
    pattern: SinkKind::FunctionCall("stack_info"),
    rule_id: "python/gen-pysa-logging",
    severity: Severity::Error,
    description: "Pysa sink: stack_info (kind: Logging)",
    cwe: Some("CWE-74"),
}];

static STACK_INFO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STACK_INFO_GEN_IMPORTS: &[&str] = &["stack_info"];

pub static STACK_INFO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "stack_info_generated",
    description: "Generated profile for stack_info from CodeQL/Pysa",
    detect_imports: STACK_INFO_GEN_IMPORTS,
    sources: STACK_INFO_GEN_SOURCES,
    sinks: STACK_INFO_GEN_SINKS,
    sanitizers: STACK_INFO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
