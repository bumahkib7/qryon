//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_TASK_JOIN_SET_JOINSET_SHUTDOWN_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_TASK_JOIN_SET_JOINSET_SHUTDOWN_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::task::join_set::JoinSet>::shutdown.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static TOKIO_TASK_JOIN_SET_JOINSET_SHUTDOWN_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_TASK_JOIN_SET_JOINSET_SHUTDOWN_GEN_IMPORTS: &[&str] =
    &["<tokio::task::join_set::JoinSet>::shutdown"];

pub static TOKIO_TASK_JOIN_SET_JOINSET_SHUTDOWN_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<tokio::task::join_set::joinset>::shutdown_generated",
    description: "Generated profile for <tokio::task::join_set::JoinSet>::shutdown from CodeQL/Pysa",
    detect_imports: TOKIO_TASK_JOIN_SET_JOINSET_SHUTDOWN_GEN_IMPORTS,
    sources: TOKIO_TASK_JOIN_SET_JOINSET_SHUTDOWN_GEN_SOURCES,
    sinks: TOKIO_TASK_JOIN_SET_JOINSET_SHUTDOWN_GEN_SINKS,
    sanitizers: TOKIO_TASK_JOIN_SET_JOINSET_SHUTDOWN_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
