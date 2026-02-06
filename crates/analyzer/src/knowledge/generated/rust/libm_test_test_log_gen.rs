//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LIBM_TEST_TEST_LOG_GEN_SOURCES: &[SourceDef] = &[];

static LIBM_TEST_TEST_LOG_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "libm_test::test_log.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static LIBM_TEST_TEST_LOG_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LIBM_TEST_TEST_LOG_GEN_IMPORTS: &[&str] = &["libm_test::test_log"];

pub static LIBM_TEST_TEST_LOG_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "libm_test::test_log_generated",
    description: "Generated profile for libm_test::test_log from CodeQL/Pysa",
    detect_imports: LIBM_TEST_TEST_LOG_GEN_IMPORTS,
    sources: LIBM_TEST_TEST_LOG_GEN_SOURCES,
    sinks: LIBM_TEST_TEST_LOG_GEN_SINKS,
    sanitizers: LIBM_TEST_TEST_LOG_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
