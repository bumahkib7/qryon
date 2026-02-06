//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MEMCHR_ARCH_ALL_MEMCHR_TWOITER_AS_CORE_ITER_TRAITS_DOUBLE_ENDED_DOUBLEENDEDITERATOR_NEXT_BACK_GEN_SOURCES: &[SourceDef] = &[
];

static MEMCHR_ARCH_ALL_MEMCHR_TWOITER_AS_CORE_ITER_TRAITS_DOUBLE_ENDED_DOUBLEENDEDITERATOR_NEXT_BACK_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<memchr::arch::all::memchr::TwoIter as core::iter::traits::double_ended::DoubleEndedIterator>::next_back.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
];

static MEMCHR_ARCH_ALL_MEMCHR_TWOITER_AS_CORE_ITER_TRAITS_DOUBLE_ENDED_DOUBLEENDEDITERATOR_NEXT_BACK_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static MEMCHR_ARCH_ALL_MEMCHR_TWOITER_AS_CORE_ITER_TRAITS_DOUBLE_ENDED_DOUBLEENDEDITERATOR_NEXT_BACK_GEN_IMPORTS: &[&str] = &[
    "<memchr::arch::all::memchr::TwoIter as core::iter::traits::double_ended::DoubleEndedIterator>::next_back",
];

pub static MEMCHR_ARCH_ALL_MEMCHR_TWOITER_AS_CORE_ITER_TRAITS_DOUBLE_ENDED_DOUBLEENDEDITERATOR_NEXT_BACK_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<memchr::arch::all::memchr::twoiter as core::iter::traits::double_ended::doubleendediterator>::next_back_generated",
    description: "Generated profile for <memchr::arch::all::memchr::TwoIter as core::iter::traits::double_ended::DoubleEndedIterator>::next_back from CodeQL/Pysa",
    detect_imports: MEMCHR_ARCH_ALL_MEMCHR_TWOITER_AS_CORE_ITER_TRAITS_DOUBLE_ENDED_DOUBLEENDEDITERATOR_NEXT_BACK_GEN_IMPORTS,
    sources: MEMCHR_ARCH_ALL_MEMCHR_TWOITER_AS_CORE_ITER_TRAITS_DOUBLE_ENDED_DOUBLEENDEDITERATOR_NEXT_BACK_GEN_SOURCES,
    sinks: MEMCHR_ARCH_ALL_MEMCHR_TWOITER_AS_CORE_ITER_TRAITS_DOUBLE_ENDED_DOUBLEENDEDITERATOR_NEXT_BACK_GEN_SINKS,
    sanitizers: MEMCHR_ARCH_ALL_MEMCHR_TWOITER_AS_CORE_ITER_TRAITS_DOUBLE_ENDED_DOUBLEENDEDITERATOR_NEXT_BACK_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
