//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_ARCH_CORE_ARCH_X86_SSE2__MM_STOREU_PD_GEN_SOURCES: &[SourceDef] = &[];

static CORE_ARCH_CORE_ARCH_X86_SSE2__MM_STOREU_PD_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "core_arch::core_arch::x86::sse2::_mm_storeu_pd.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static CORE_ARCH_CORE_ARCH_X86_SSE2__MM_STOREU_PD_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_ARCH_CORE_ARCH_X86_SSE2__MM_STOREU_PD_GEN_IMPORTS: &[&str] =
    &["core_arch::core_arch::x86::sse2::_mm_storeu_pd"];

pub static CORE_ARCH_CORE_ARCH_X86_SSE2__MM_STOREU_PD_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "core_arch::core_arch::x86::sse2::_mm_storeu_pd_generated",
        description: "Generated profile for core_arch::core_arch::x86::sse2::_mm_storeu_pd from CodeQL/Pysa",
        detect_imports: CORE_ARCH_CORE_ARCH_X86_SSE2__MM_STOREU_PD_GEN_IMPORTS,
        sources: CORE_ARCH_CORE_ARCH_X86_SSE2__MM_STOREU_PD_GEN_SOURCES,
        sinks: CORE_ARCH_CORE_ARCH_X86_SSE2__MM_STOREU_PD_GEN_SINKS,
        sanitizers: CORE_ARCH_CORE_ARCH_X86_SSE2__MM_STOREU_PD_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
