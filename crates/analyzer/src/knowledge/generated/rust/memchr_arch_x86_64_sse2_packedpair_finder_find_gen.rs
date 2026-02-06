//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MEMCHR_ARCH_X86_64_SSE2_PACKEDPAIR_FINDER_FIND_GEN_SOURCES: &[SourceDef] = &[];

static MEMCHR_ARCH_X86_64_SSE2_PACKEDPAIR_FINDER_FIND_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<memchr::arch::x86_64::sse2::packedpair::Finder>::find.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[1] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "<memchr::arch::x86_64::sse2::packedpair::Finder>::find.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static MEMCHR_ARCH_X86_64_SSE2_PACKEDPAIR_FINDER_FIND_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MEMCHR_ARCH_X86_64_SSE2_PACKEDPAIR_FINDER_FIND_GEN_IMPORTS: &[&str] =
    &["<memchr::arch::x86_64::sse2::packedpair::Finder>::find"];

pub static MEMCHR_ARCH_X86_64_SSE2_PACKEDPAIR_FINDER_FIND_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<memchr::arch::x86_64::sse2::packedpair::finder>::find_generated",
        description: "Generated profile for <memchr::arch::x86_64::sse2::packedpair::Finder>::find from CodeQL/Pysa",
        detect_imports: MEMCHR_ARCH_X86_64_SSE2_PACKEDPAIR_FINDER_FIND_GEN_IMPORTS,
        sources: MEMCHR_ARCH_X86_64_SSE2_PACKEDPAIR_FINDER_FIND_GEN_SOURCES,
        sinks: MEMCHR_ARCH_X86_64_SSE2_PACKEDPAIR_FINDER_FIND_GEN_SINKS,
        sanitizers: MEMCHR_ARCH_X86_64_SSE2_PACKEDPAIR_FINDER_FIND_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
