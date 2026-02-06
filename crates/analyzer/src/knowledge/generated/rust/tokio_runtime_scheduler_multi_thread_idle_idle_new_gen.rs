//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_RUNTIME_SCHEDULER_MULTI_THREAD_IDLE_IDLE_NEW_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_RUNTIME_SCHEDULER_MULTI_THREAD_IDLE_IDLE_NEW_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::runtime::scheduler::multi_thread::idle::Idle>::new.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static TOKIO_RUNTIME_SCHEDULER_MULTI_THREAD_IDLE_IDLE_NEW_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_RUNTIME_SCHEDULER_MULTI_THREAD_IDLE_IDLE_NEW_GEN_IMPORTS: &[&str] =
    &["<tokio::runtime::scheduler::multi_thread::idle::Idle>::new"];

pub static TOKIO_RUNTIME_SCHEDULER_MULTI_THREAD_IDLE_IDLE_NEW_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::runtime::scheduler::multi_thread::idle::idle>::new_generated",
        description: "Generated profile for <tokio::runtime::scheduler::multi_thread::idle::Idle>::new from CodeQL/Pysa",
        detect_imports: TOKIO_RUNTIME_SCHEDULER_MULTI_THREAD_IDLE_IDLE_NEW_GEN_IMPORTS,
        sources: TOKIO_RUNTIME_SCHEDULER_MULTI_THREAD_IDLE_IDLE_NEW_GEN_SOURCES,
        sinks: TOKIO_RUNTIME_SCHEDULER_MULTI_THREAD_IDLE_IDLE_NEW_GEN_SINKS,
        sanitizers: TOKIO_RUNTIME_SCHEDULER_MULTI_THREAD_IDLE_IDLE_NEW_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
