//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_VEC_VEC_AS_CORE_CONVERT_FROM_FROM_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_VEC_VEC_AS_CORE_CONVERT_FROM_FROM_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<alloc::vec::Vec as core::convert::From>::from.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static ALLOC_VEC_VEC_AS_CORE_CONVERT_FROM_FROM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOC_VEC_VEC_AS_CORE_CONVERT_FROM_FROM_GEN_IMPORTS: &[&str] =
    &["<alloc::vec::Vec as core::convert::From>::from"];

pub static ALLOC_VEC_VEC_AS_CORE_CONVERT_FROM_FROM_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<alloc::vec::vec as core::convert::from>::from_generated",
        description: "Generated profile for <alloc::vec::Vec as core::convert::From>::from from CodeQL/Pysa",
        detect_imports: ALLOC_VEC_VEC_AS_CORE_CONVERT_FROM_FROM_GEN_IMPORTS,
        sources: ALLOC_VEC_VEC_AS_CORE_CONVERT_FROM_FROM_GEN_SOURCES,
        sinks: ALLOC_VEC_VEC_AS_CORE_CONVERT_FROM_FROM_GEN_SINKS,
        sanitizers: ALLOC_VEC_VEC_AS_CORE_CONVERT_FROM_FROM_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
