//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static COMPILER_BUILTINS_MATH_FULL_AVAILABILITY_RINTF_GEN_SOURCES: &[SourceDef] = &[];

static COMPILER_BUILTINS_MATH_FULL_AVAILABILITY_RINTF_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "compiler_builtins::math::full_availability::rintf.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static COMPILER_BUILTINS_MATH_FULL_AVAILABILITY_RINTF_GEN_SANITIZERS: &[SanitizerDef] = &[];

static COMPILER_BUILTINS_MATH_FULL_AVAILABILITY_RINTF_GEN_IMPORTS: &[&str] =
    &["compiler_builtins::math::full_availability::rintf"];

pub static COMPILER_BUILTINS_MATH_FULL_AVAILABILITY_RINTF_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "compiler_builtins::math::full_availability::rintf_generated",
        description: "Generated profile for compiler_builtins::math::full_availability::rintf from CodeQL/Pysa",
        detect_imports: COMPILER_BUILTINS_MATH_FULL_AVAILABILITY_RINTF_GEN_IMPORTS,
        sources: COMPILER_BUILTINS_MATH_FULL_AVAILABILITY_RINTF_GEN_SOURCES,
        sinks: COMPILER_BUILTINS_MATH_FULL_AVAILABILITY_RINTF_GEN_SINKS,
        sanitizers: COMPILER_BUILTINS_MATH_FULL_AVAILABILITY_RINTF_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
