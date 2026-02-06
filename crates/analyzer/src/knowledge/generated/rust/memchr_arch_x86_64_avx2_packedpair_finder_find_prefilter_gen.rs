//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MEMCHR_ARCH_X86_64_AVX2_PACKEDPAIR_FINDER_FIND_PREFILTER_GEN_SOURCES: &[SourceDef] = &[];

static MEMCHR_ARCH_X86_64_AVX2_PACKEDPAIR_FINDER_FIND_PREFILTER_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<memchr::arch::x86_64::avx2::packedpair::Finder>::find_prefilter.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static MEMCHR_ARCH_X86_64_AVX2_PACKEDPAIR_FINDER_FIND_PREFILTER_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static MEMCHR_ARCH_X86_64_AVX2_PACKEDPAIR_FINDER_FIND_PREFILTER_GEN_IMPORTS: &[&str] =
    &["<memchr::arch::x86_64::avx2::packedpair::Finder>::find_prefilter"];

pub static MEMCHR_ARCH_X86_64_AVX2_PACKEDPAIR_FINDER_FIND_PREFILTER_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<memchr::arch::x86_64::avx2::packedpair::finder>::find_prefilter_generated",
        description: "Generated profile for <memchr::arch::x86_64::avx2::packedpair::Finder>::find_prefilter from CodeQL/Pysa",
        detect_imports: MEMCHR_ARCH_X86_64_AVX2_PACKEDPAIR_FINDER_FIND_PREFILTER_GEN_IMPORTS,
        sources: MEMCHR_ARCH_X86_64_AVX2_PACKEDPAIR_FINDER_FIND_PREFILTER_GEN_SOURCES,
        sinks: MEMCHR_ARCH_X86_64_AVX2_PACKEDPAIR_FINDER_FIND_PREFILTER_GEN_SINKS,
        sanitizers: MEMCHR_ARCH_X86_64_AVX2_PACKEDPAIR_FINDER_FIND_PREFILTER_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
