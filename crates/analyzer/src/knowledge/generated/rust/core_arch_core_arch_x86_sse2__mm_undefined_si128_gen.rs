//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_ARCH_CORE_ARCH_X86_SSE2__MM_UNDEFINED_SI128_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "core_arch::core_arch::x86::sse2::_mm_undefined_si128.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: constant-source)",
}];

static CORE_ARCH_CORE_ARCH_X86_SSE2__MM_UNDEFINED_SI128_GEN_SINKS: &[SinkDef] = &[];

static CORE_ARCH_CORE_ARCH_X86_SSE2__MM_UNDEFINED_SI128_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_ARCH_CORE_ARCH_X86_SSE2__MM_UNDEFINED_SI128_GEN_IMPORTS: &[&str] =
    &["core_arch::core_arch::x86::sse2::_mm_undefined_si128"];

pub static CORE_ARCH_CORE_ARCH_X86_SSE2__MM_UNDEFINED_SI128_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "core_arch::core_arch::x86::sse2::_mm_undefined_si128_generated",
        description: "Generated profile for core_arch::core_arch::x86::sse2::_mm_undefined_si128 from CodeQL/Pysa",
        detect_imports: CORE_ARCH_CORE_ARCH_X86_SSE2__MM_UNDEFINED_SI128_GEN_IMPORTS,
        sources: CORE_ARCH_CORE_ARCH_X86_SSE2__MM_UNDEFINED_SI128_GEN_SOURCES,
        sinks: CORE_ARCH_CORE_ARCH_X86_SSE2__MM_UNDEFINED_SI128_GEN_SINKS,
        sanitizers: CORE_ARCH_CORE_ARCH_X86_SSE2__MM_UNDEFINED_SI128_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
