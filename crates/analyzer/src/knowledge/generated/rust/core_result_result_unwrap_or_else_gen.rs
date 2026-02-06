//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_RESULT_RESULT_UNWRAP_OR_ELSE_GEN_SOURCES: &[SourceDef] = &[];

static CORE_RESULT_RESULT_UNWRAP_OR_ELSE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<core::result::Result>::unwrap_or_else.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static CORE_RESULT_RESULT_UNWRAP_OR_ELSE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_RESULT_RESULT_UNWRAP_OR_ELSE_GEN_IMPORTS: &[&str] =
    &["<core::result::Result>::unwrap_or_else"];

pub static CORE_RESULT_RESULT_UNWRAP_OR_ELSE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<core::result::result>::unwrap_or_else_generated",
    description: "Generated profile for <core::result::Result>::unwrap_or_else from CodeQL/Pysa",
    detect_imports: CORE_RESULT_RESULT_UNWRAP_OR_ELSE_GEN_IMPORTS,
    sources: CORE_RESULT_RESULT_UNWRAP_OR_ELSE_GEN_SOURCES,
    sinks: CORE_RESULT_RESULT_UNWRAP_OR_ELSE_GEN_SINKS,
    sanitizers: CORE_RESULT_RESULT_UNWRAP_OR_ELSE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
