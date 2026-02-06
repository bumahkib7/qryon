//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_SYNC_BATCH_SEMAPHORE_SEMAPHORE_RELEASE_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_SYNC_BATCH_SEMAPHORE_SEMAPHORE_RELEASE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::sync::batch_semaphore::Semaphore>::release.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_SYNC_BATCH_SEMAPHORE_SEMAPHORE_RELEASE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_SYNC_BATCH_SEMAPHORE_SEMAPHORE_RELEASE_GEN_IMPORTS: &[&str] =
    &["<tokio::sync::batch_semaphore::Semaphore>::release"];

pub static TOKIO_SYNC_BATCH_SEMAPHORE_SEMAPHORE_RELEASE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::sync::batch_semaphore::semaphore>::release_generated",
        description: "Generated profile for <tokio::sync::batch_semaphore::Semaphore>::release from CodeQL/Pysa",
        detect_imports: TOKIO_SYNC_BATCH_SEMAPHORE_SEMAPHORE_RELEASE_GEN_IMPORTS,
        sources: TOKIO_SYNC_BATCH_SEMAPHORE_SEMAPHORE_RELEASE_GEN_SOURCES,
        sinks: TOKIO_SYNC_BATCH_SEMAPHORE_SEMAPHORE_RELEASE_GEN_SINKS,
        sanitizers: TOKIO_SYNC_BATCH_SEMAPHORE_SEMAPHORE_RELEASE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
