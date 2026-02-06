//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYNC_MPMC_WAKER_WAKER_UNREGISTER_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYNC_MPMC_WAKER_WAKER_UNREGISTER_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::sync::mpmc::waker::Waker>::unregister.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static STD_SYNC_MPMC_WAKER_WAKER_UNREGISTER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYNC_MPMC_WAKER_WAKER_UNREGISTER_GEN_IMPORTS: &[&str] =
    &["<std::sync::mpmc::waker::Waker>::unregister"];

pub static STD_SYNC_MPMC_WAKER_WAKER_UNREGISTER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<std::sync::mpmc::waker::waker>::unregister_generated",
    description: "Generated profile for <std::sync::mpmc::waker::Waker>::unregister from CodeQL/Pysa",
    detect_imports: STD_SYNC_MPMC_WAKER_WAKER_UNREGISTER_GEN_IMPORTS,
    sources: STD_SYNC_MPMC_WAKER_WAKER_UNREGISTER_GEN_SOURCES,
    sinks: STD_SYNC_MPMC_WAKER_WAKER_UNREGISTER_GEN_SINKS,
    sanitizers: STD_SYNC_MPMC_WAKER_WAKER_UNREGISTER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
