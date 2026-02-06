//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_VEC_VEC_INTO_RAW_PARTS_WITH_ALLOC_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_VEC_VEC_INTO_RAW_PARTS_WITH_ALLOC_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<alloc::vec::Vec>::into_raw_parts_with_alloc.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static ALLOC_VEC_VEC_INTO_RAW_PARTS_WITH_ALLOC_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOC_VEC_VEC_INTO_RAW_PARTS_WITH_ALLOC_GEN_IMPORTS: &[&str] =
    &["<alloc::vec::Vec>::into_raw_parts_with_alloc"];

pub static ALLOC_VEC_VEC_INTO_RAW_PARTS_WITH_ALLOC_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<alloc::vec::vec>::into_raw_parts_with_alloc_generated",
        description: "Generated profile for <alloc::vec::Vec>::into_raw_parts_with_alloc from CodeQL/Pysa",
        detect_imports: ALLOC_VEC_VEC_INTO_RAW_PARTS_WITH_ALLOC_GEN_IMPORTS,
        sources: ALLOC_VEC_VEC_INTO_RAW_PARTS_WITH_ALLOC_GEN_SOURCES,
        sinks: ALLOC_VEC_VEC_INTO_RAW_PARTS_WITH_ALLOC_GEN_SINKS,
        sanitizers: ALLOC_VEC_VEC_INTO_RAW_PARTS_WITH_ALLOC_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
