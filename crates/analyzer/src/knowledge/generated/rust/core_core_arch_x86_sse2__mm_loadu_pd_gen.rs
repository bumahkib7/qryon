//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_CORE_ARCH_X86_SSE2__MM_LOADU_PD_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "core::core_arch::x86::sse2::_mm_loadu_pd.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: constant-source)",
}];

static CORE_CORE_ARCH_X86_SSE2__MM_LOADU_PD_GEN_SINKS: &[SinkDef] = &[];

static CORE_CORE_ARCH_X86_SSE2__MM_LOADU_PD_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_CORE_ARCH_X86_SSE2__MM_LOADU_PD_GEN_IMPORTS: &[&str] =
    &["core::core_arch::x86::sse2::_mm_loadu_pd"];

pub static CORE_CORE_ARCH_X86_SSE2__MM_LOADU_PD_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "core::core_arch::x86::sse2::_mm_loadu_pd_generated",
    description: "Generated profile for core::core_arch::x86::sse2::_mm_loadu_pd from CodeQL/Pysa",
    detect_imports: CORE_CORE_ARCH_X86_SSE2__MM_LOADU_PD_GEN_IMPORTS,
    sources: CORE_CORE_ARCH_X86_SSE2__MM_LOADU_PD_GEN_SOURCES,
    sinks: CORE_CORE_ARCH_X86_SSE2__MM_LOADU_PD_GEN_SINKS,
    sanitizers: CORE_CORE_ARCH_X86_SSE2__MM_LOADU_PD_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
