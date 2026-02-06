//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSIC_AS_INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSICDEFINITION_PRINT_RESULT_C_GEN_SOURCES: &[SourceDef] = &[
];

static INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSIC_AS_INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSICDEFINITION_PRINT_RESULT_C_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<intrinsic-test::common::intrinsic::Intrinsic as intrinsic-test::common::intrinsic::IntrinsicDefinition>::print_result_c.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSIC_AS_INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSICDEFINITION_PRINT_RESULT_C_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSIC_AS_INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSICDEFINITION_PRINT_RESULT_C_GEN_IMPORTS: &[&str] = &[
    "<intrinsic-test::common::intrinsic::Intrinsic as intrinsic-test::common::intrinsic::IntrinsicDefinition>::print_result_c",
];

pub static INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSIC_AS_INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSICDEFINITION_PRINT_RESULT_C_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<intrinsic_test::common::intrinsic::intrinsic as intrinsic_test::common::intrinsic::intrinsicdefinition>::print_result_c_generated",
    description: "Generated profile for <intrinsic-test::common::intrinsic::Intrinsic as intrinsic-test::common::intrinsic::IntrinsicDefinition>::print_result_c from CodeQL/Pysa",
    detect_imports: INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSIC_AS_INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSICDEFINITION_PRINT_RESULT_C_GEN_IMPORTS,
    sources: INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSIC_AS_INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSICDEFINITION_PRINT_RESULT_C_GEN_SOURCES,
    sinks: INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSIC_AS_INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSICDEFINITION_PRINT_RESULT_C_GEN_SINKS,
    sanitizers: INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSIC_AS_INTRINSIC_TEST_COMMON_INTRINSIC_INTRINSICDEFINITION_PRINT_RESULT_C_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
