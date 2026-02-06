//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_ALLOC_RUST_OOM_GEN_SOURCES: &[SourceDef] = &[];

static STD_ALLOC_RUST_OOM_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "std::alloc::rust_oom.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static STD_ALLOC_RUST_OOM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_ALLOC_RUST_OOM_GEN_IMPORTS: &[&str] = &["std::alloc::rust_oom"];

pub static STD_ALLOC_RUST_OOM_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::alloc::rust_oom_generated",
    description: "Generated profile for std::alloc::rust_oom from CodeQL/Pysa",
    detect_imports: STD_ALLOC_RUST_OOM_GEN_IMPORTS,
    sources: STD_ALLOC_RUST_OOM_GEN_SOURCES,
    sinks: STD_ALLOC_RUST_OOM_GEN_SINKS,
    sanitizers: STD_ALLOC_RUST_OOM_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
