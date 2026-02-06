//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AS_LIBM_TEST_GENERATE_SPACED_SPACEDINPUT_GET_CASES_3_GEN_SOURCES: &[SourceDef] = &[];

static AS_LIBM_TEST_GENERATE_SPACED_SPACEDINPUT_GET_CASES_3_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<(,,,) as libm_test::generate::spaced::SpacedInput>::get_cases.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static AS_LIBM_TEST_GENERATE_SPACED_SPACEDINPUT_GET_CASES_3_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AS_LIBM_TEST_GENERATE_SPACED_SPACEDINPUT_GET_CASES_3_GEN_IMPORTS: &[&str] =
    &["<(,,,) as libm_test::generate::spaced::SpacedInput>::get_cases"];

pub static AS_LIBM_TEST_GENERATE_SPACED_SPACEDINPUT_GET_CASES_3_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<(,,,) as libm_test::generate::spaced::spacedinput>::get_cases_generated",
        description: "Generated profile for <(,,,) as libm_test::generate::spaced::SpacedInput>::get_cases from CodeQL/Pysa",
        detect_imports: AS_LIBM_TEST_GENERATE_SPACED_SPACEDINPUT_GET_CASES_3_GEN_IMPORTS,
        sources: AS_LIBM_TEST_GENERATE_SPACED_SPACEDINPUT_GET_CASES_3_GEN_SOURCES,
        sinks: AS_LIBM_TEST_GENERATE_SPACED_SPACEDINPUT_GET_CASES_3_GEN_SINKS,
        sanitizers: AS_LIBM_TEST_GENERATE_SPACED_SPACEDINPUT_GET_CASES_3_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
