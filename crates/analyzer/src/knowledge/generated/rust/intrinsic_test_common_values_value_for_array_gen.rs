//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INTRINSIC_TEST_COMMON_VALUES_VALUE_FOR_ARRAY_GEN_SOURCES: &[SourceDef] = &[];

static INTRINSIC_TEST_COMMON_VALUES_VALUE_FOR_ARRAY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "intrinsic-test::common::values::value_for_array.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static INTRINSIC_TEST_COMMON_VALUES_VALUE_FOR_ARRAY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static INTRINSIC_TEST_COMMON_VALUES_VALUE_FOR_ARRAY_GEN_IMPORTS: &[&str] =
    &["intrinsic-test::common::values::value_for_array"];

pub static INTRINSIC_TEST_COMMON_VALUES_VALUE_FOR_ARRAY_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "intrinsic_test::common::values::value_for_array_generated",
        description: "Generated profile for intrinsic-test::common::values::value_for_array from CodeQL/Pysa",
        detect_imports: INTRINSIC_TEST_COMMON_VALUES_VALUE_FOR_ARRAY_GEN_IMPORTS,
        sources: INTRINSIC_TEST_COMMON_VALUES_VALUE_FOR_ARRAY_GEN_SOURCES,
        sinks: INTRINSIC_TEST_COMMON_VALUES_VALUE_FOR_ARRAY_GEN_SINKS,
        sanitizers: INTRINSIC_TEST_COMMON_VALUES_VALUE_FOR_ARRAY_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
