//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_UTIL_TASK_TASK_TRACKER_TASKTRACKERWAITFUTURE_AS_CORE_FMT_DEBUG_FMT_GEN_SOURCES:
    &[SourceDef] = &[];

static TOKIO_UTIL_TASK_TASK_TRACKER_TASKTRACKERWAITFUTURE_AS_CORE_FMT_DEBUG_FMT_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<tokio_util::task::task_tracker::TaskTrackerWaitFuture as core::fmt::Debug>::fmt.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static TOKIO_UTIL_TASK_TASK_TRACKER_TASKTRACKERWAITFUTURE_AS_CORE_FMT_DEBUG_FMT_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static TOKIO_UTIL_TASK_TASK_TRACKER_TASKTRACKERWAITFUTURE_AS_CORE_FMT_DEBUG_FMT_GEN_IMPORTS:
    &[&str] = &["<tokio_util::task::task_tracker::TaskTrackerWaitFuture as core::fmt::Debug>::fmt"];

pub static TOKIO_UTIL_TASK_TASK_TRACKER_TASKTRACKERWAITFUTURE_AS_CORE_FMT_DEBUG_FMT_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<tokio_util::task::task_tracker::tasktrackerwaitfuture as core::fmt::debug>::fmt_generated",
    description: "Generated profile for <tokio_util::task::task_tracker::TaskTrackerWaitFuture as core::fmt::Debug>::fmt from CodeQL/Pysa",
    detect_imports:
        TOKIO_UTIL_TASK_TASK_TRACKER_TASKTRACKERWAITFUTURE_AS_CORE_FMT_DEBUG_FMT_GEN_IMPORTS,
    sources: TOKIO_UTIL_TASK_TASK_TRACKER_TASKTRACKERWAITFUTURE_AS_CORE_FMT_DEBUG_FMT_GEN_SOURCES,
    sinks: TOKIO_UTIL_TASK_TASK_TRACKER_TASKTRACKERWAITFUTURE_AS_CORE_FMT_DEBUG_FMT_GEN_SINKS,
    sanitizers:
        TOKIO_UTIL_TASK_TASK_TRACKER_TASKTRACKERWAITFUTURE_AS_CORE_FMT_DEBUG_FMT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
