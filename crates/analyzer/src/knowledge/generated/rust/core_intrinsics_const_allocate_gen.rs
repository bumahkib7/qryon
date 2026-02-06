//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_INTRINSICS_CONST_ALLOCATE_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "core::intrinsics::const_allocate.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: pointer-invalidate)",
}];

static CORE_INTRINSICS_CONST_ALLOCATE_GEN_SINKS: &[SinkDef] = &[];

static CORE_INTRINSICS_CONST_ALLOCATE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_INTRINSICS_CONST_ALLOCATE_GEN_IMPORTS: &[&str] = &["core::intrinsics::const_allocate"];

pub static CORE_INTRINSICS_CONST_ALLOCATE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "core::intrinsics::const_allocate_generated",
    description: "Generated profile for core::intrinsics::const_allocate from CodeQL/Pysa",
    detect_imports: CORE_INTRINSICS_CONST_ALLOCATE_GEN_IMPORTS,
    sources: CORE_INTRINSICS_CONST_ALLOCATE_GEN_SOURCES,
    sinks: CORE_INTRINSICS_CONST_ALLOCATE_GEN_SINKS,
    sanitizers: CORE_INTRINSICS_CONST_ALLOCATE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
