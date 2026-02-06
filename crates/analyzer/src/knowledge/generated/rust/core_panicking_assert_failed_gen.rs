//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_PANICKING_ASSERT_FAILED_GEN_SOURCES: &[SourceDef] = &[];

static CORE_PANICKING_ASSERT_FAILED_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "core::panicking::assert_failed.Argument[3]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[3] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static CORE_PANICKING_ASSERT_FAILED_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_PANICKING_ASSERT_FAILED_GEN_IMPORTS: &[&str] = &["core::panicking::assert_failed"];

pub static CORE_PANICKING_ASSERT_FAILED_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "core::panicking::assert_failed_generated",
    description: "Generated profile for core::panicking::assert_failed from CodeQL/Pysa",
    detect_imports: CORE_PANICKING_ASSERT_FAILED_GEN_IMPORTS,
    sources: CORE_PANICKING_ASSERT_FAILED_GEN_SOURCES,
    sinks: CORE_PANICKING_ASSERT_FAILED_GEN_SINKS,
    sanitizers: CORE_PANICKING_ASSERT_FAILED_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
