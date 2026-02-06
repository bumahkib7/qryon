//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_SYNC_BATCH_SEMAPHORE_ACQUIRE_AS_CORE_OPS_DROP_DROP_DROP_GEN_SOURCES: &[SourceDef] =
    &[];

static TOKIO_SYNC_BATCH_SEMAPHORE_ACQUIRE_AS_CORE_OPS_DROP_DROP_DROP_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<tokio::sync::batch_semaphore::Acquire as core::ops::drop::Drop>::drop.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static TOKIO_SYNC_BATCH_SEMAPHORE_ACQUIRE_AS_CORE_OPS_DROP_DROP_DROP_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static TOKIO_SYNC_BATCH_SEMAPHORE_ACQUIRE_AS_CORE_OPS_DROP_DROP_DROP_GEN_IMPORTS: &[&str] =
    &["<tokio::sync::batch_semaphore::Acquire as core::ops::drop::Drop>::drop"];

pub static TOKIO_SYNC_BATCH_SEMAPHORE_ACQUIRE_AS_CORE_OPS_DROP_DROP_DROP_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<tokio::sync::batch_semaphore::acquire as core::ops::drop::drop>::drop_generated",
    description: "Generated profile for <tokio::sync::batch_semaphore::Acquire as core::ops::drop::Drop>::drop from CodeQL/Pysa",
    detect_imports: TOKIO_SYNC_BATCH_SEMAPHORE_ACQUIRE_AS_CORE_OPS_DROP_DROP_DROP_GEN_IMPORTS,
    sources: TOKIO_SYNC_BATCH_SEMAPHORE_ACQUIRE_AS_CORE_OPS_DROP_DROP_DROP_GEN_SOURCES,
    sinks: TOKIO_SYNC_BATCH_SEMAPHORE_ACQUIRE_AS_CORE_OPS_DROP_DROP_DROP_GEN_SINKS,
    sanitizers: TOKIO_SYNC_BATCH_SEMAPHORE_ACQUIRE_AS_CORE_OPS_DROP_DROP_DROP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
