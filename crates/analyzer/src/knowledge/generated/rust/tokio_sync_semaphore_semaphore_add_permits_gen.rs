//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_SYNC_SEMAPHORE_SEMAPHORE_ADD_PERMITS_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_SYNC_SEMAPHORE_SEMAPHORE_ADD_PERMITS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::sync::semaphore::Semaphore>::add_permits.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_SYNC_SEMAPHORE_SEMAPHORE_ADD_PERMITS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_SYNC_SEMAPHORE_SEMAPHORE_ADD_PERMITS_GEN_IMPORTS: &[&str] =
    &["<tokio::sync::semaphore::Semaphore>::add_permits"];

pub static TOKIO_SYNC_SEMAPHORE_SEMAPHORE_ADD_PERMITS_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::sync::semaphore::semaphore>::add_permits_generated",
        description: "Generated profile for <tokio::sync::semaphore::Semaphore>::add_permits from CodeQL/Pysa",
        detect_imports: TOKIO_SYNC_SEMAPHORE_SEMAPHORE_ADD_PERMITS_GEN_IMPORTS,
        sources: TOKIO_SYNC_SEMAPHORE_SEMAPHORE_ADD_PERMITS_GEN_SOURCES,
        sinks: TOKIO_SYNC_SEMAPHORE_SEMAPHORE_ADD_PERMITS_GEN_SINKS,
        sanitizers: TOKIO_SYNC_SEMAPHORE_SEMAPHORE_ADD_PERMITS_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
