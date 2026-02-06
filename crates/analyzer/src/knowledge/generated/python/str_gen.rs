//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STR_GEN_SOURCES: &[SourceDef] = &[];

static STR_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "str.format",
    pattern: SinkKind::FunctionCall("str.format"),
    rule_id: "python/gen-pysa-formatstring",
    severity: Severity::Error,
    description: "Pysa sink: str.format (kind: FormatString)",
    cwe: Some("CWE-74"),
}];

static STR_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STR_GEN_IMPORTS: &[&str] = &["str"];

pub static STR_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "str_generated",
    description: "Generated profile for str from CodeQL/Pysa",
    detect_imports: STR_GEN_IMPORTS,
    sources: STR_GEN_SOURCES,
    sinks: STR_GEN_SINKS,
    sanitizers: STR_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
