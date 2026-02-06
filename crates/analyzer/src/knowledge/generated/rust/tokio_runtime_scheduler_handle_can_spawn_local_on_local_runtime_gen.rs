//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_RUNTIME_SCHEDULER_HANDLE_CAN_SPAWN_LOCAL_ON_LOCAL_RUNTIME_GEN_SOURCES: &[SourceDef] =
    &[];

static TOKIO_RUNTIME_SCHEDULER_HANDLE_CAN_SPAWN_LOCAL_ON_LOCAL_RUNTIME_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<tokio::runtime::scheduler::Handle>::can_spawn_local_on_local_runtime.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static TOKIO_RUNTIME_SCHEDULER_HANDLE_CAN_SPAWN_LOCAL_ON_LOCAL_RUNTIME_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static TOKIO_RUNTIME_SCHEDULER_HANDLE_CAN_SPAWN_LOCAL_ON_LOCAL_RUNTIME_GEN_IMPORTS: &[&str] =
    &["<tokio::runtime::scheduler::Handle>::can_spawn_local_on_local_runtime"];

pub static TOKIO_RUNTIME_SCHEDULER_HANDLE_CAN_SPAWN_LOCAL_ON_LOCAL_RUNTIME_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<tokio::runtime::scheduler::handle>::can_spawn_local_on_local_runtime_generated",
    description: "Generated profile for <tokio::runtime::scheduler::Handle>::can_spawn_local_on_local_runtime from CodeQL/Pysa",
    detect_imports: TOKIO_RUNTIME_SCHEDULER_HANDLE_CAN_SPAWN_LOCAL_ON_LOCAL_RUNTIME_GEN_IMPORTS,
    sources: TOKIO_RUNTIME_SCHEDULER_HANDLE_CAN_SPAWN_LOCAL_ON_LOCAL_RUNTIME_GEN_SOURCES,
    sinks: TOKIO_RUNTIME_SCHEDULER_HANDLE_CAN_SPAWN_LOCAL_ON_LOCAL_RUNTIME_GEN_SINKS,
    sanitizers: TOKIO_RUNTIME_SCHEDULER_HANDLE_CAN_SPAWN_LOCAL_ON_LOCAL_RUNTIME_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
