//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PROC_MACRO_LITERAL_F64_UNSUFFIXED_GEN_SOURCES: &[SourceDef] = &[];

static PROC_MACRO_LITERAL_F64_UNSUFFIXED_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<proc_macro::Literal>::f64_unsuffixed.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static PROC_MACRO_LITERAL_F64_UNSUFFIXED_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PROC_MACRO_LITERAL_F64_UNSUFFIXED_GEN_IMPORTS: &[&str] =
    &["<proc_macro::Literal>::f64_unsuffixed"];

pub static PROC_MACRO_LITERAL_F64_UNSUFFIXED_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<proc_macro::literal>::f64_unsuffixed_generated",
    description: "Generated profile for <proc_macro::Literal>::f64_unsuffixed from CodeQL/Pysa",
    detect_imports: PROC_MACRO_LITERAL_F64_UNSUFFIXED_GEN_IMPORTS,
    sources: PROC_MACRO_LITERAL_F64_UNSUFFIXED_GEN_SOURCES,
    sinks: PROC_MACRO_LITERAL_F64_UNSUFFIXED_GEN_SINKS,
    sanitizers: PROC_MACRO_LITERAL_F64_UNSUFFIXED_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
