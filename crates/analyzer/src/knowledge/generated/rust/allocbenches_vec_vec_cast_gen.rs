//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOCBENCHES_VEC_VEC_CAST_GEN_SOURCES: &[SourceDef] = &[];

static ALLOCBENCHES_VEC_VEC_CAST_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "allocbenches::vec::vec_cast.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static ALLOCBENCHES_VEC_VEC_CAST_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOCBENCHES_VEC_VEC_CAST_GEN_IMPORTS: &[&str] = &["allocbenches::vec::vec_cast"];

pub static ALLOCBENCHES_VEC_VEC_CAST_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "allocbenches::vec::vec_cast_generated",
    description: "Generated profile for allocbenches::vec::vec_cast from CodeQL/Pysa",
    detect_imports: ALLOCBENCHES_VEC_VEC_CAST_GEN_IMPORTS,
    sources: ALLOCBENCHES_VEC_VEC_CAST_GEN_SOURCES,
    sinks: ALLOCBENCHES_VEC_VEC_CAST_GEN_SINKS,
    sanitizers: ALLOCBENCHES_VEC_VEC_CAST_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
