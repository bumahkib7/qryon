//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_VEC_VEC_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SOURCES:
    &[SourceDef] = &[];

static ALLOC_VEC_VEC_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<alloc::vec::Vec as core::iter::traits::collect::IntoIterator>::into_iter.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
];

static ALLOC_VEC_VEC_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static ALLOC_VEC_VEC_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_IMPORTS: &[&str] =
    &["<alloc::vec::Vec as core::iter::traits::collect::IntoIterator>::into_iter"];

pub static ALLOC_VEC_VEC_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<alloc::vec::vec as core::iter::traits::collect::intoiterator>::into_iter_generated",
    description: "Generated profile for <alloc::vec::Vec as core::iter::traits::collect::IntoIterator>::into_iter from CodeQL/Pysa",
    detect_imports: ALLOC_VEC_VEC_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_IMPORTS,
    sources: ALLOC_VEC_VEC_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SOURCES,
    sinks: ALLOC_VEC_VEC_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SINKS,
    sanitizers: ALLOC_VEC_VEC_AS_CORE_ITER_TRAITS_COLLECT_INTOITERATOR_INTO_ITER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
