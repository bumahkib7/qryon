//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SELECT_NTH_UNSTABLE_BY_GEN_SOURCES: &[SourceDef] = &[];

static SELECT_NTH_UNSTABLE_BY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<[]>::select_nth_unstable_by.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static SELECT_NTH_UNSTABLE_BY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SELECT_NTH_UNSTABLE_BY_GEN_IMPORTS: &[&str] = &["<[]>::select_nth_unstable_by"];

pub static SELECT_NTH_UNSTABLE_BY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<[]>::select_nth_unstable_by_generated",
    description: "Generated profile for <[]>::select_nth_unstable_by from CodeQL/Pysa",
    detect_imports: SELECT_NTH_UNSTABLE_BY_GEN_IMPORTS,
    sources: SELECT_NTH_UNSTABLE_BY_GEN_SOURCES,
    sinks: SELECT_NTH_UNSTABLE_BY_GEN_SINKS,
    sanitizers: SELECT_NTH_UNSTABLE_BY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
