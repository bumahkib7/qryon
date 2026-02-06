//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_VEC_VEC_TRY_WITH_CAPACITY_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_VEC_VEC_TRY_WITH_CAPACITY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<alloc::vec::Vec>::try_with_capacity.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ALLOC_VEC_VEC_TRY_WITH_CAPACITY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOC_VEC_VEC_TRY_WITH_CAPACITY_GEN_IMPORTS: &[&str] =
    &["<alloc::vec::Vec>::try_with_capacity"];

pub static ALLOC_VEC_VEC_TRY_WITH_CAPACITY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<alloc::vec::vec>::try_with_capacity_generated",
    description: "Generated profile for <alloc::vec::Vec>::try_with_capacity from CodeQL/Pysa",
    detect_imports: ALLOC_VEC_VEC_TRY_WITH_CAPACITY_GEN_IMPORTS,
    sources: ALLOC_VEC_VEC_TRY_WITH_CAPACITY_GEN_SOURCES,
    sinks: ALLOC_VEC_VEC_TRY_WITH_CAPACITY_GEN_SINKS,
    sanitizers: ALLOC_VEC_VEC_TRY_WITH_CAPACITY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
