//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_ARCH_CORE_ARCH_X86_AVX512F__MM512_UNDEFINED_PS_GEN_SOURCES: &[SourceDef] =
    &[SourceDef {
        name: "core_arch::core_arch::x86::avx512f::_mm512_undefined_ps.ReturnValue",
        pattern: SourceKind::FunctionCall(""),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue (kind: constant-source)",
    }];

static CORE_ARCH_CORE_ARCH_X86_AVX512F__MM512_UNDEFINED_PS_GEN_SINKS: &[SinkDef] = &[];

static CORE_ARCH_CORE_ARCH_X86_AVX512F__MM512_UNDEFINED_PS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_ARCH_CORE_ARCH_X86_AVX512F__MM512_UNDEFINED_PS_GEN_IMPORTS: &[&str] =
    &["core_arch::core_arch::x86::avx512f::_mm512_undefined_ps"];

pub static CORE_ARCH_CORE_ARCH_X86_AVX512F__MM512_UNDEFINED_PS_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "core_arch::core_arch::x86::avx512f::_mm512_undefined_ps_generated",
        description: "Generated profile for core_arch::core_arch::x86::avx512f::_mm512_undefined_ps from CodeQL/Pysa",
        detect_imports: CORE_ARCH_CORE_ARCH_X86_AVX512F__MM512_UNDEFINED_PS_GEN_IMPORTS,
        sources: CORE_ARCH_CORE_ARCH_X86_AVX512F__MM512_UNDEFINED_PS_GEN_SOURCES,
        sinks: CORE_ARCH_CORE_ARCH_X86_AVX512F__MM512_UNDEFINED_PS_GEN_SINKS,
        sanitizers: CORE_ARCH_CORE_ARCH_X86_AVX512F__MM512_UNDEFINED_PS_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
