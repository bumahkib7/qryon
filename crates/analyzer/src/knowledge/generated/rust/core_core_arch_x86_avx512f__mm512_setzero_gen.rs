//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_CORE_ARCH_X86_AVX512F__MM512_SETZERO_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "core::core_arch::x86::avx512f::_mm512_setzero.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: constant-source)",
}];

static CORE_CORE_ARCH_X86_AVX512F__MM512_SETZERO_GEN_SINKS: &[SinkDef] = &[];

static CORE_CORE_ARCH_X86_AVX512F__MM512_SETZERO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_CORE_ARCH_X86_AVX512F__MM512_SETZERO_GEN_IMPORTS: &[&str] =
    &["core::core_arch::x86::avx512f::_mm512_setzero"];

pub static CORE_CORE_ARCH_X86_AVX512F__MM512_SETZERO_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "core::core_arch::x86::avx512f::_mm512_setzero_generated",
        description: "Generated profile for core::core_arch::x86::avx512f::_mm512_setzero from CodeQL/Pysa",
        detect_imports: CORE_CORE_ARCH_X86_AVX512F__MM512_SETZERO_GEN_IMPORTS,
        sources: CORE_CORE_ARCH_X86_AVX512F__MM512_SETZERO_GEN_SOURCES,
        sinks: CORE_CORE_ARCH_X86_AVX512F__MM512_SETZERO_GEN_SINKS,
        sanitizers: CORE_CORE_ARCH_X86_AVX512F__MM512_SETZERO_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
