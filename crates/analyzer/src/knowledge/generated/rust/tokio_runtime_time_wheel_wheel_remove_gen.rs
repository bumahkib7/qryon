//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_RUNTIME_TIME_WHEEL_WHEEL_REMOVE_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_RUNTIME_TIME_WHEEL_WHEEL_REMOVE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::runtime::time::wheel::Wheel>::remove.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_RUNTIME_TIME_WHEEL_WHEEL_REMOVE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_RUNTIME_TIME_WHEEL_WHEEL_REMOVE_GEN_IMPORTS: &[&str] =
    &["<tokio::runtime::time::wheel::Wheel>::remove"];

pub static TOKIO_RUNTIME_TIME_WHEEL_WHEEL_REMOVE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<tokio::runtime::time::wheel::wheel>::remove_generated",
    description: "Generated profile for <tokio::runtime::time::wheel::Wheel>::remove from CodeQL/Pysa",
    detect_imports: TOKIO_RUNTIME_TIME_WHEEL_WHEEL_REMOVE_GEN_IMPORTS,
    sources: TOKIO_RUNTIME_TIME_WHEEL_WHEEL_REMOVE_GEN_SOURCES,
    sinks: TOKIO_RUNTIME_TIME_WHEEL_WHEEL_REMOVE_GEN_SINKS,
    sanitizers: TOKIO_RUNTIME_TIME_WHEEL_WHEEL_REMOVE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
