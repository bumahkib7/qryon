//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_CORE_ARCH_X86_AVX__MM256_STOREU2_M128D_GEN_SOURCES: &[SourceDef] = &[];

static CORE_CORE_ARCH_X86_AVX__MM256_STOREU2_M128D_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "core::core_arch::x86::avx::_mm256_storeu2_m128d.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[0] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "core::core_arch::x86::avx::_mm256_storeu2_m128d.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[1] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
];

static CORE_CORE_ARCH_X86_AVX__MM256_STOREU2_M128D_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_CORE_ARCH_X86_AVX__MM256_STOREU2_M128D_GEN_IMPORTS: &[&str] =
    &["core::core_arch::x86::avx::_mm256_storeu2_m128d"];

pub static CORE_CORE_ARCH_X86_AVX__MM256_STOREU2_M128D_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "core::core_arch::x86::avx::_mm256_storeu2_m128d_generated",
        description: "Generated profile for core::core_arch::x86::avx::_mm256_storeu2_m128d from CodeQL/Pysa",
        detect_imports: CORE_CORE_ARCH_X86_AVX__MM256_STOREU2_M128D_GEN_IMPORTS,
        sources: CORE_CORE_ARCH_X86_AVX__MM256_STOREU2_M128D_GEN_SOURCES,
        sinks: CORE_CORE_ARCH_X86_AVX__MM256_STOREU2_M128D_GEN_SINKS,
        sanitizers: CORE_CORE_ARCH_X86_AVX__MM256_STOREU2_M128D_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
