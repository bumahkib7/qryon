//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MEMCHR_ARCH_ALL_MEMCHR_THREEITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SOURCES:
    &[SourceDef] = &[];

static MEMCHR_ARCH_ALL_MEMCHR_THREEITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<memchr::arch::all::memchr::ThreeIter as core::iter::traits::iterator::Iterator>::next.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static MEMCHR_ARCH_ALL_MEMCHR_THREEITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static MEMCHR_ARCH_ALL_MEMCHR_THREEITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_IMPORTS:
    &[&str] =
    &["<memchr::arch::all::memchr::ThreeIter as core::iter::traits::iterator::Iterator>::next"];

pub static MEMCHR_ARCH_ALL_MEMCHR_THREEITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<memchr::arch::all::memchr::threeiter as core::iter::traits::iterator::iterator>::next_generated",
    description: "Generated profile for <memchr::arch::all::memchr::ThreeIter as core::iter::traits::iterator::Iterator>::next from CodeQL/Pysa",
    detect_imports: MEMCHR_ARCH_ALL_MEMCHR_THREEITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_IMPORTS,
    sources: MEMCHR_ARCH_ALL_MEMCHR_THREEITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SOURCES,
    sinks: MEMCHR_ARCH_ALL_MEMCHR_THREEITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SINKS,
    sanitizers: MEMCHR_ARCH_ALL_MEMCHR_THREEITER_AS_CORE_ITER_TRAITS_ITERATOR_ITERATOR_NEXT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
