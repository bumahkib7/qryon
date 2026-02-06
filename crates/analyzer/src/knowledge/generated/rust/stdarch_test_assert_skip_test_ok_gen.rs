//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STDARCH_TEST_ASSERT_SKIP_TEST_OK_GEN_SOURCES: &[SourceDef] = &[];

static STDARCH_TEST_ASSERT_SKIP_TEST_OK_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "stdarch_test::assert_skip_test_ok.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
    SinkDef {
        name: "stdarch_test::assert_skip_test_ok.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[1] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static STDARCH_TEST_ASSERT_SKIP_TEST_OK_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STDARCH_TEST_ASSERT_SKIP_TEST_OK_GEN_IMPORTS: &[&str] =
    &["stdarch_test::assert_skip_test_ok"];

pub static STDARCH_TEST_ASSERT_SKIP_TEST_OK_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "stdarch_test::assert_skip_test_ok_generated",
    description: "Generated profile for stdarch_test::assert_skip_test_ok from CodeQL/Pysa",
    detect_imports: STDARCH_TEST_ASSERT_SKIP_TEST_OK_GEN_IMPORTS,
    sources: STDARCH_TEST_ASSERT_SKIP_TEST_OK_GEN_SOURCES,
    sinks: STDARCH_TEST_ASSERT_SKIP_TEST_OK_GEN_SINKS,
    sanitizers: STDARCH_TEST_ASSERT_SKIP_TEST_OK_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
