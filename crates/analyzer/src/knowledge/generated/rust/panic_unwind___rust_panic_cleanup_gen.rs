//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PANIC_UNWIND___RUST_PANIC_CLEANUP_GEN_SOURCES: &[SourceDef] = &[];

static PANIC_UNWIND___RUST_PANIC_CLEANUP_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "panic_unwind::__rust_panic_cleanup.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static PANIC_UNWIND___RUST_PANIC_CLEANUP_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PANIC_UNWIND___RUST_PANIC_CLEANUP_GEN_IMPORTS: &[&str] =
    &["panic_unwind::__rust_panic_cleanup"];

pub static PANIC_UNWIND___RUST_PANIC_CLEANUP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "panic_unwind::__rust_panic_cleanup_generated",
    description: "Generated profile for panic_unwind::__rust_panic_cleanup from CodeQL/Pysa",
    detect_imports: PANIC_UNWIND___RUST_PANIC_CLEANUP_GEN_IMPORTS,
    sources: PANIC_UNWIND___RUST_PANIC_CLEANUP_GEN_SOURCES,
    sinks: PANIC_UNWIND___RUST_PANIC_CLEANUP_GEN_SINKS,
    sanitizers: PANIC_UNWIND___RUST_PANIC_CLEANUP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
