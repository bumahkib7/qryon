//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LIBM_MATH_ATAN_ATAN_GEN_SOURCES: &[SourceDef] = &[];

static LIBM_MATH_ATAN_ATAN_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "libm::math::atan::atan.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static LIBM_MATH_ATAN_ATAN_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LIBM_MATH_ATAN_ATAN_GEN_IMPORTS: &[&str] = &["libm::math::atan::atan"];

pub static LIBM_MATH_ATAN_ATAN_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "libm::math::atan::atan_generated",
    description: "Generated profile for libm::math::atan::atan from CodeQL/Pysa",
    detect_imports: LIBM_MATH_ATAN_ATAN_GEN_IMPORTS,
    sources: LIBM_MATH_ATAN_ATAN_GEN_SOURCES,
    sinks: LIBM_MATH_ATAN_ATAN_GEN_SINKS,
    sanitizers: LIBM_MATH_ATAN_ATAN_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
