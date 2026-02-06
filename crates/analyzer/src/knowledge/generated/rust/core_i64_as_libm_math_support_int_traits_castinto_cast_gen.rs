//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_I64_AS_LIBM_MATH_SUPPORT_INT_TRAITS_CASTINTO_CAST_GEN_SOURCES: &[SourceDef] = &[];

static CORE_I64_AS_LIBM_MATH_SUPPORT_INT_TRAITS_CASTINTO_CAST_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<core::i64 as libm::math::support::int_traits::CastInto>::cast.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static CORE_I64_AS_LIBM_MATH_SUPPORT_INT_TRAITS_CASTINTO_CAST_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_I64_AS_LIBM_MATH_SUPPORT_INT_TRAITS_CASTINTO_CAST_GEN_IMPORTS: &[&str] =
    &["<core::i64 as libm::math::support::int_traits::CastInto>::cast"];

pub static CORE_I64_AS_LIBM_MATH_SUPPORT_INT_TRAITS_CASTINTO_CAST_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<core::i64 as libm::math::support::int_traits::castinto>::cast_generated",
        description: "Generated profile for <core::i64 as libm::math::support::int_traits::CastInto>::cast from CodeQL/Pysa",
        detect_imports: CORE_I64_AS_LIBM_MATH_SUPPORT_INT_TRAITS_CASTINTO_CAST_GEN_IMPORTS,
        sources: CORE_I64_AS_LIBM_MATH_SUPPORT_INT_TRAITS_CASTINTO_CAST_GEN_SOURCES,
        sinks: CORE_I64_AS_LIBM_MATH_SUPPORT_INT_TRAITS_CASTINTO_CAST_GEN_SINKS,
        sanitizers: CORE_I64_AS_LIBM_MATH_SUPPORT_INT_TRAITS_CASTINTO_CAST_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
