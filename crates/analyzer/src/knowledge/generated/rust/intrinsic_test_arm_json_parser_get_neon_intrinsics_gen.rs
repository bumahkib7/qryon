//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INTRINSIC_TEST_ARM_JSON_PARSER_GET_NEON_INTRINSICS_GEN_SOURCES: &[SourceDef] =
    &[SourceDef {
        name: "intrinsic-test::arm::json_parser::get_neon_intrinsics.ReturnValue",
        pattern: SourceKind::FunctionCall(""),
        taint_label: "file_input",
        description: "CodeQL source: ReturnValue (kind: file)",
    }];

static INTRINSIC_TEST_ARM_JSON_PARSER_GET_NEON_INTRINSICS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "intrinsic-test::arm::json_parser::get_neon_intrinsics.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[0] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static INTRINSIC_TEST_ARM_JSON_PARSER_GET_NEON_INTRINSICS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static INTRINSIC_TEST_ARM_JSON_PARSER_GET_NEON_INTRINSICS_GEN_IMPORTS: &[&str] =
    &["intrinsic-test::arm::json_parser::get_neon_intrinsics"];

pub static INTRINSIC_TEST_ARM_JSON_PARSER_GET_NEON_INTRINSICS_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "intrinsic_test::arm::json_parser::get_neon_intrinsics_generated",
        description: "Generated profile for intrinsic-test::arm::json_parser::get_neon_intrinsics from CodeQL/Pysa",
        detect_imports: INTRINSIC_TEST_ARM_JSON_PARSER_GET_NEON_INTRINSICS_GEN_IMPORTS,
        sources: INTRINSIC_TEST_ARM_JSON_PARSER_GET_NEON_INTRINSICS_GEN_SOURCES,
        sinks: INTRINSIC_TEST_ARM_JSON_PARSER_GET_NEON_INTRINSICS_GEN_SINKS,
        sanitizers: INTRINSIC_TEST_ARM_JSON_PARSER_GET_NEON_INTRINSICS_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
