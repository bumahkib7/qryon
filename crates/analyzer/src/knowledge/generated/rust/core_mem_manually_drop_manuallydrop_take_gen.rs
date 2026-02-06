//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_MEM_MANUALLY_DROP_MANUALLYDROP_TAKE_GEN_SOURCES: &[SourceDef] = &[];

static CORE_MEM_MANUALLY_DROP_MANUALLYDROP_TAKE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<core::mem::manually_drop::ManuallyDrop>::take.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static CORE_MEM_MANUALLY_DROP_MANUALLYDROP_TAKE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_MEM_MANUALLY_DROP_MANUALLYDROP_TAKE_GEN_IMPORTS: &[&str] =
    &["<core::mem::manually_drop::ManuallyDrop>::take"];

pub static CORE_MEM_MANUALLY_DROP_MANUALLYDROP_TAKE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<core::mem::manually_drop::manuallydrop>::take_generated",
        description: "Generated profile for <core::mem::manually_drop::ManuallyDrop>::take from CodeQL/Pysa",
        detect_imports: CORE_MEM_MANUALLY_DROP_MANUALLYDROP_TAKE_GEN_IMPORTS,
        sources: CORE_MEM_MANUALLY_DROP_MANUALLYDROP_TAKE_GEN_SOURCES,
        sinks: CORE_MEM_MANUALLY_DROP_MANUALLYDROP_TAKE_GEN_SINKS,
        sanitizers: CORE_MEM_MANUALLY_DROP_MANUALLYDROP_TAKE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
