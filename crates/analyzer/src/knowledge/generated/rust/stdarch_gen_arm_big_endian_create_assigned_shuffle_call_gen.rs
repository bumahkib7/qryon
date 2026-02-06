//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STDARCH_GEN_ARM_BIG_ENDIAN_CREATE_ASSIGNED_SHUFFLE_CALL_GEN_SOURCES: &[SourceDef] = &[];

static STDARCH_GEN_ARM_BIG_ENDIAN_CREATE_ASSIGNED_SHUFFLE_CALL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "stdarch-gen-arm::big_endian::create_assigned_shuffle_call.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "stdarch-gen-arm::big_endian::create_assigned_shuffle_call.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[1] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static STDARCH_GEN_ARM_BIG_ENDIAN_CREATE_ASSIGNED_SHUFFLE_CALL_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static STDARCH_GEN_ARM_BIG_ENDIAN_CREATE_ASSIGNED_SHUFFLE_CALL_GEN_IMPORTS: &[&str] =
    &["stdarch-gen-arm::big_endian::create_assigned_shuffle_call"];

pub static STDARCH_GEN_ARM_BIG_ENDIAN_CREATE_ASSIGNED_SHUFFLE_CALL_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "stdarch_gen_arm::big_endian::create_assigned_shuffle_call_generated",
        description: "Generated profile for stdarch-gen-arm::big_endian::create_assigned_shuffle_call from CodeQL/Pysa",
        detect_imports: STDARCH_GEN_ARM_BIG_ENDIAN_CREATE_ASSIGNED_SHUFFLE_CALL_GEN_IMPORTS,
        sources: STDARCH_GEN_ARM_BIG_ENDIAN_CREATE_ASSIGNED_SHUFFLE_CALL_GEN_SOURCES,
        sinks: STDARCH_GEN_ARM_BIG_ENDIAN_CREATE_ASSIGNED_SHUFFLE_CALL_GEN_SINKS,
        sanitizers: STDARCH_GEN_ARM_BIG_ENDIAN_CREATE_ASSIGNED_SHUFFLE_CALL_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
