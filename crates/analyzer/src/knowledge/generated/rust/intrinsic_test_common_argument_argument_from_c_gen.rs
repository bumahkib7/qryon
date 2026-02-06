//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INTRINSIC_TEST_COMMON_ARGUMENT_ARGUMENT_FROM_C_GEN_SOURCES: &[SourceDef] = &[];

static INTRINSIC_TEST_COMMON_ARGUMENT_ARGUMENT_FROM_C_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<intrinsic-test::common::argument::Argument>::from_c.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[1] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static INTRINSIC_TEST_COMMON_ARGUMENT_ARGUMENT_FROM_C_GEN_SANITIZERS: &[SanitizerDef] = &[];

static INTRINSIC_TEST_COMMON_ARGUMENT_ARGUMENT_FROM_C_GEN_IMPORTS: &[&str] =
    &["<intrinsic-test::common::argument::Argument>::from_c"];

pub static INTRINSIC_TEST_COMMON_ARGUMENT_ARGUMENT_FROM_C_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<intrinsic_test::common::argument::argument>::from_c_generated",
        description: "Generated profile for <intrinsic-test::common::argument::Argument>::from_c from CodeQL/Pysa",
        detect_imports: INTRINSIC_TEST_COMMON_ARGUMENT_ARGUMENT_FROM_C_GEN_IMPORTS,
        sources: INTRINSIC_TEST_COMMON_ARGUMENT_ARGUMENT_FROM_C_GEN_SOURCES,
        sinks: INTRINSIC_TEST_COMMON_ARGUMENT_ARGUMENT_FROM_C_GEN_SINKS,
        sanitizers: INTRINSIC_TEST_COMMON_ARGUMENT_ARGUMENT_FROM_C_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
