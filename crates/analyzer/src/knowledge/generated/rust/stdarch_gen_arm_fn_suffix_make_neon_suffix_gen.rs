//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STDARCH_GEN_ARM_FN_SUFFIX_MAKE_NEON_SUFFIX_GEN_SOURCES: &[SourceDef] = &[];

static STDARCH_GEN_ARM_FN_SUFFIX_MAKE_NEON_SUFFIX_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "stdarch-gen-arm::fn_suffix::make_neon_suffix.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static STDARCH_GEN_ARM_FN_SUFFIX_MAKE_NEON_SUFFIX_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STDARCH_GEN_ARM_FN_SUFFIX_MAKE_NEON_SUFFIX_GEN_IMPORTS: &[&str] =
    &["stdarch-gen-arm::fn_suffix::make_neon_suffix"];

pub static STDARCH_GEN_ARM_FN_SUFFIX_MAKE_NEON_SUFFIX_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "stdarch_gen_arm::fn_suffix::make_neon_suffix_generated",
        description: "Generated profile for stdarch-gen-arm::fn_suffix::make_neon_suffix from CodeQL/Pysa",
        detect_imports: STDARCH_GEN_ARM_FN_SUFFIX_MAKE_NEON_SUFFIX_GEN_IMPORTS,
        sources: STDARCH_GEN_ARM_FN_SUFFIX_MAKE_NEON_SUFFIX_GEN_SOURCES,
        sinks: STDARCH_GEN_ARM_FN_SUFFIX_MAKE_NEON_SUFFIX_GEN_SINKS,
        sanitizers: STDARCH_GEN_ARM_FN_SUFFIX_MAKE_NEON_SUFFIX_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
