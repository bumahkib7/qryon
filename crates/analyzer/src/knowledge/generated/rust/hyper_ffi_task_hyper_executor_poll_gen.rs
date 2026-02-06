//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_FFI_TASK_HYPER_EXECUTOR_POLL_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "hyper::ffi::task::hyper_executor_poll.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: pointer-invalidate)",
}];

static HYPER_FFI_TASK_HYPER_EXECUTOR_POLL_GEN_SINKS: &[SinkDef] = &[];

static HYPER_FFI_TASK_HYPER_EXECUTOR_POLL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HYPER_FFI_TASK_HYPER_EXECUTOR_POLL_GEN_IMPORTS: &[&str] =
    &["hyper::ffi::task::hyper_executor_poll"];

pub static HYPER_FFI_TASK_HYPER_EXECUTOR_POLL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "hyper::ffi::task::hyper_executor_poll_generated",
    description: "Generated profile for hyper::ffi::task::hyper_executor_poll from CodeQL/Pysa",
    detect_imports: HYPER_FFI_TASK_HYPER_EXECUTOR_POLL_GEN_IMPORTS,
    sources: HYPER_FFI_TASK_HYPER_EXECUTOR_POLL_GEN_SOURCES,
    sinks: HYPER_FFI_TASK_HYPER_EXECUTOR_POLL_GEN_SINKS,
    sanitizers: HYPER_FFI_TASK_HYPER_EXECUTOR_POLL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
