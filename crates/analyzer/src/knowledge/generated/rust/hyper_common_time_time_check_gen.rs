//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_COMMON_TIME_TIME_CHECK_GEN_SOURCES: &[SourceDef] = &[];

static HYPER_COMMON_TIME_TIME_CHECK_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<hyper::common::time::Time>::check.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[1] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static HYPER_COMMON_TIME_TIME_CHECK_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HYPER_COMMON_TIME_TIME_CHECK_GEN_IMPORTS: &[&str] = &["<hyper::common::time::Time>::check"];

pub static HYPER_COMMON_TIME_TIME_CHECK_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<hyper::common::time::time>::check_generated",
    description: "Generated profile for <hyper::common::time::Time>::check from CodeQL/Pysa",
    detect_imports: HYPER_COMMON_TIME_TIME_CHECK_GEN_IMPORTS,
    sources: HYPER_COMMON_TIME_TIME_CHECK_GEN_SOURCES,
    sinks: HYPER_COMMON_TIME_TIME_CHECK_GEN_SINKS,
    sanitizers: HYPER_COMMON_TIME_TIME_CHECK_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
