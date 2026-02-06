//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_PTR_DROP_IN_PLACE_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "core::ptr::drop_in_place.Argument[0]",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: Argument[0] (kind: pointer-invalidate)",
}];

static CORE_PTR_DROP_IN_PLACE_GEN_SINKS: &[SinkDef] = &[];

static CORE_PTR_DROP_IN_PLACE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_PTR_DROP_IN_PLACE_GEN_IMPORTS: &[&str] = &["core::ptr::drop_in_place"];

pub static CORE_PTR_DROP_IN_PLACE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "core::ptr::drop_in_place_generated",
    description: "Generated profile for core::ptr::drop_in_place from CodeQL/Pysa",
    detect_imports: CORE_PTR_DROP_IN_PLACE_GEN_IMPORTS,
    sources: CORE_PTR_DROP_IN_PLACE_GEN_SOURCES,
    sinks: CORE_PTR_DROP_IN_PLACE_GEN_SINKS,
    sanitizers: CORE_PTR_DROP_IN_PLACE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
