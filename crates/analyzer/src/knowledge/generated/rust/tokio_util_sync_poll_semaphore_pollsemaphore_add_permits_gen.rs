//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_UTIL_SYNC_POLL_SEMAPHORE_POLLSEMAPHORE_ADD_PERMITS_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_UTIL_SYNC_POLL_SEMAPHORE_POLLSEMAPHORE_ADD_PERMITS_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<tokio_util::sync::poll_semaphore::PollSemaphore>::add_permits.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static TOKIO_UTIL_SYNC_POLL_SEMAPHORE_POLLSEMAPHORE_ADD_PERMITS_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static TOKIO_UTIL_SYNC_POLL_SEMAPHORE_POLLSEMAPHORE_ADD_PERMITS_GEN_IMPORTS: &[&str] =
    &["<tokio_util::sync::poll_semaphore::PollSemaphore>::add_permits"];

pub static TOKIO_UTIL_SYNC_POLL_SEMAPHORE_POLLSEMAPHORE_ADD_PERMITS_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio_util::sync::poll_semaphore::pollsemaphore>::add_permits_generated",
        description: "Generated profile for <tokio_util::sync::poll_semaphore::PollSemaphore>::add_permits from CodeQL/Pysa",
        detect_imports: TOKIO_UTIL_SYNC_POLL_SEMAPHORE_POLLSEMAPHORE_ADD_PERMITS_GEN_IMPORTS,
        sources: TOKIO_UTIL_SYNC_POLL_SEMAPHORE_POLLSEMAPHORE_ADD_PERMITS_GEN_SOURCES,
        sinks: TOKIO_UTIL_SYNC_POLL_SEMAPHORE_POLLSEMAPHORE_ADD_PERMITS_GEN_SINKS,
        sanitizers: TOKIO_UTIL_SYNC_POLL_SEMAPHORE_POLLSEMAPHORE_ADD_PERMITS_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
