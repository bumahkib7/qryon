//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MEMCHR_ARCH_GENERIC_MEMCHR_ITER_NEXT_BACK_GEN_SOURCES: &[SourceDef] = &[];

static MEMCHR_ARCH_GENERIC_MEMCHR_ITER_NEXT_BACK_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<memchr::arch::generic::memchr::Iter>::next_back.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static MEMCHR_ARCH_GENERIC_MEMCHR_ITER_NEXT_BACK_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MEMCHR_ARCH_GENERIC_MEMCHR_ITER_NEXT_BACK_GEN_IMPORTS: &[&str] =
    &["<memchr::arch::generic::memchr::Iter>::next_back"];

pub static MEMCHR_ARCH_GENERIC_MEMCHR_ITER_NEXT_BACK_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<memchr::arch::generic::memchr::iter>::next_back_generated",
        description: "Generated profile for <memchr::arch::generic::memchr::Iter>::next_back from CodeQL/Pysa",
        detect_imports: MEMCHR_ARCH_GENERIC_MEMCHR_ITER_NEXT_BACK_GEN_IMPORTS,
        sources: MEMCHR_ARCH_GENERIC_MEMCHR_ITER_NEXT_BACK_GEN_SOURCES,
        sinks: MEMCHR_ARCH_GENERIC_MEMCHR_ITER_NEXT_BACK_GEN_SINKS,
        sanitizers: MEMCHR_ARCH_GENERIC_MEMCHR_ITER_NEXT_BACK_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
