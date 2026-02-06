//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STDARCH_GEN_ARM_INPUT_INPUTSET_INTO_ITER_GEN_SOURCES: &[SourceDef] = &[];

static STDARCH_GEN_ARM_INPUT_INPUTSET_INTO_ITER_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<stdarch-gen-arm::input::InputSet>::into_iter.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static STDARCH_GEN_ARM_INPUT_INPUTSET_INTO_ITER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STDARCH_GEN_ARM_INPUT_INPUTSET_INTO_ITER_GEN_IMPORTS: &[&str] =
    &["<stdarch-gen-arm::input::InputSet>::into_iter"];

pub static STDARCH_GEN_ARM_INPUT_INPUTSET_INTO_ITER_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<stdarch_gen_arm::input::inputset>::into_iter_generated",
        description: "Generated profile for <stdarch-gen-arm::input::InputSet>::into_iter from CodeQL/Pysa",
        detect_imports: STDARCH_GEN_ARM_INPUT_INPUTSET_INTO_ITER_GEN_IMPORTS,
        sources: STDARCH_GEN_ARM_INPUT_INPUTSET_INTO_ITER_GEN_SOURCES,
        sinks: STDARCH_GEN_ARM_INPUT_INPUTSET_INTO_ITER_GEN_SINKS,
        sanitizers: STDARCH_GEN_ARM_INPUT_INPUTSET_INTO_ITER_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
