//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_RUNTIME_TASK_RAW_RAWTASK_SET_QUEUE_NEXT_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_RUNTIME_TASK_RAW_RAWTASK_SET_QUEUE_NEXT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::runtime::task::raw::RawTask>::set_queue_next.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static TOKIO_RUNTIME_TASK_RAW_RAWTASK_SET_QUEUE_NEXT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_RUNTIME_TASK_RAW_RAWTASK_SET_QUEUE_NEXT_GEN_IMPORTS: &[&str] =
    &["<tokio::runtime::task::raw::RawTask>::set_queue_next"];

pub static TOKIO_RUNTIME_TASK_RAW_RAWTASK_SET_QUEUE_NEXT_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::runtime::task::raw::rawtask>::set_queue_next_generated",
        description: "Generated profile for <tokio::runtime::task::raw::RawTask>::set_queue_next from CodeQL/Pysa",
        detect_imports: TOKIO_RUNTIME_TASK_RAW_RAWTASK_SET_QUEUE_NEXT_GEN_IMPORTS,
        sources: TOKIO_RUNTIME_TASK_RAW_RAWTASK_SET_QUEUE_NEXT_GEN_SOURCES,
        sinks: TOKIO_RUNTIME_TASK_RAW_RAWTASK_SET_QUEUE_NEXT_GEN_SINKS,
        sanitizers: TOKIO_RUNTIME_TASK_RAW_RAWTASK_SET_QUEUE_NEXT_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
