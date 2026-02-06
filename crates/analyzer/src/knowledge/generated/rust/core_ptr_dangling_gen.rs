//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_PTR_DANGLING_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "core::ptr::dangling.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: pointer-invalidate)",
}];

static CORE_PTR_DANGLING_GEN_SINKS: &[SinkDef] = &[];

static CORE_PTR_DANGLING_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_PTR_DANGLING_GEN_IMPORTS: &[&str] = &["core::ptr::dangling"];

pub static CORE_PTR_DANGLING_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "core::ptr::dangling_generated",
    description: "Generated profile for core::ptr::dangling from CodeQL/Pysa",
    detect_imports: CORE_PTR_DANGLING_GEN_IMPORTS,
    sources: CORE_PTR_DANGLING_GEN_SOURCES,
    sinks: CORE_PTR_DANGLING_GEN_SINKS,
    sanitizers: CORE_PTR_DANGLING_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
