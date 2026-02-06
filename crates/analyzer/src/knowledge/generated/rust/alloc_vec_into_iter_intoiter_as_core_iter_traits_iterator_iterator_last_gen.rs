//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_VEC_INTO_ITER_INTOITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SOURCES:
    &[SourceDef] = &[];

static ALLOC_VEC_INTO_ITER_INTOITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<alloc::vec::into_iter::IntoIter as core::iter::traits::iterator::Iterator>::last.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static ALLOC_VEC_INTO_ITER_INTOITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static ALLOC_VEC_INTO_ITER_INTOITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_IMPORTS:
    &[&str] =
    &["<alloc::vec::into_iter::IntoIter as core::iter::traits::iterator::Iterator>::last"];

pub static ALLOC_VEC_INTO_ITER_INTOITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<alloc::vec::into_iter::intoiter as core::iter::traits::iterator::iterator>::last_generated",
    description: "Generated profile for <alloc::vec::into_iter::IntoIter as core::iter::traits::iterator::Iterator>::last from CodeQL/Pysa",
    detect_imports:
        ALLOC_VEC_INTO_ITER_INTOITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_IMPORTS,
    sources: ALLOC_VEC_INTO_ITER_INTOITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SOURCES,
    sinks: ALLOC_VEC_INTO_ITER_INTOITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SINKS,
    sanitizers:
        ALLOC_VEC_INTO_ITER_INTOITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_LAST_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
