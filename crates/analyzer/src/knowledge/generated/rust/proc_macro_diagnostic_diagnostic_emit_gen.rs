//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PROC_MACRO_DIAGNOSTIC_DIAGNOSTIC_EMIT_GEN_SOURCES: &[SourceDef] = &[];

static PROC_MACRO_DIAGNOSTIC_DIAGNOSTIC_EMIT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<proc_macro::diagnostic::Diagnostic>::emit.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static PROC_MACRO_DIAGNOSTIC_DIAGNOSTIC_EMIT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PROC_MACRO_DIAGNOSTIC_DIAGNOSTIC_EMIT_GEN_IMPORTS: &[&str] =
    &["<proc_macro::diagnostic::Diagnostic>::emit"];

pub static PROC_MACRO_DIAGNOSTIC_DIAGNOSTIC_EMIT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<proc_macro::diagnostic::diagnostic>::emit_generated",
    description: "Generated profile for <proc_macro::diagnostic::Diagnostic>::emit from CodeQL/Pysa",
    detect_imports: PROC_MACRO_DIAGNOSTIC_DIAGNOSTIC_EMIT_GEN_IMPORTS,
    sources: PROC_MACRO_DIAGNOSTIC_DIAGNOSTIC_EMIT_GEN_SOURCES,
    sinks: PROC_MACRO_DIAGNOSTIC_DIAGNOSTIC_EMIT_GEN_SINKS,
    sanitizers: PROC_MACRO_DIAGNOSTIC_DIAGNOSTIC_EMIT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
