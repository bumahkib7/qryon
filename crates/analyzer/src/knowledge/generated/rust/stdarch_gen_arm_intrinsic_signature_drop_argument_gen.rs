//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STDARCH_GEN_ARM_INTRINSIC_SIGNATURE_DROP_ARGUMENT_GEN_SOURCES: &[SourceDef] = &[];

static STDARCH_GEN_ARM_INTRINSIC_SIGNATURE_DROP_ARGUMENT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<stdarch-gen-arm::intrinsic::Signature>::drop_argument.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static STDARCH_GEN_ARM_INTRINSIC_SIGNATURE_DROP_ARGUMENT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STDARCH_GEN_ARM_INTRINSIC_SIGNATURE_DROP_ARGUMENT_GEN_IMPORTS: &[&str] =
    &["<stdarch-gen-arm::intrinsic::Signature>::drop_argument"];

pub static STDARCH_GEN_ARM_INTRINSIC_SIGNATURE_DROP_ARGUMENT_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<stdarch_gen_arm::intrinsic::signature>::drop_argument_generated",
        description: "Generated profile for <stdarch-gen-arm::intrinsic::Signature>::drop_argument from CodeQL/Pysa",
        detect_imports: STDARCH_GEN_ARM_INTRINSIC_SIGNATURE_DROP_ARGUMENT_GEN_IMPORTS,
        sources: STDARCH_GEN_ARM_INTRINSIC_SIGNATURE_DROP_ARGUMENT_GEN_SOURCES,
        sinks: STDARCH_GEN_ARM_INTRINSIC_SIGNATURE_DROP_ARGUMENT_GEN_SINKS,
        sanitizers: STDARCH_GEN_ARM_INTRINSIC_SIGNATURE_DROP_ARGUMENT_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
