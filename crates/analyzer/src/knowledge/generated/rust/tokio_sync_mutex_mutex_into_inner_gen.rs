//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_SYNC_MUTEX_MUTEX_INTO_INNER_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_SYNC_MUTEX_MUTEX_INTO_INNER_GEN_SINKS: &[SinkDef] = &[];

static TOKIO_SYNC_MUTEX_MUTEX_INTO_INNER_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "<tokio::sync::mutex::Mutex>::into_inner.Argument[self].Field[tokio::sync::mutex::Mutex::c].Field[core::cell::UnsafeCell::value]",
    pattern: SanitizerKind::Function(
        "Argument[self].Field[tokio::sync::mutex::Mutex::c].Field[core::cell::UnsafeCell::value]",
    ),
    sanitizes: "general",
    description: "CodeQL sanitizer: Argument[self].Field[tokio::sync::mutex::Mutex::c].Field[core::cell::UnsafeCell::value]",
}];

static TOKIO_SYNC_MUTEX_MUTEX_INTO_INNER_GEN_IMPORTS: &[&str] =
    &["<tokio::sync::mutex::Mutex>::into_inner"];

pub static TOKIO_SYNC_MUTEX_MUTEX_INTO_INNER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<tokio::sync::mutex::mutex>::into_inner_generated",
    description: "Generated profile for <tokio::sync::mutex::Mutex>::into_inner from CodeQL/Pysa",
    detect_imports: TOKIO_SYNC_MUTEX_MUTEX_INTO_INNER_GEN_IMPORTS,
    sources: TOKIO_SYNC_MUTEX_MUTEX_INTO_INNER_GEN_SOURCES,
    sinks: TOKIO_SYNC_MUTEX_MUTEX_INTO_INNER_GEN_SINKS,
    sanitizers: TOKIO_SYNC_MUTEX_MUTEX_INTO_INNER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
