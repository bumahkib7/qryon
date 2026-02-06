//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PROC_MACRO_BRIDGE_SYMBOL_SYMBOL_NEW_IDENT_GEN_SOURCES: &[SourceDef] = &[];

static PROC_MACRO_BRIDGE_SYMBOL_SYMBOL_NEW_IDENT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<proc_macro::bridge::symbol::Symbol>::new_ident.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static PROC_MACRO_BRIDGE_SYMBOL_SYMBOL_NEW_IDENT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PROC_MACRO_BRIDGE_SYMBOL_SYMBOL_NEW_IDENT_GEN_IMPORTS: &[&str] =
    &["<proc_macro::bridge::symbol::Symbol>::new_ident"];

pub static PROC_MACRO_BRIDGE_SYMBOL_SYMBOL_NEW_IDENT_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<proc_macro::bridge::symbol::symbol>::new_ident_generated",
        description: "Generated profile for <proc_macro::bridge::symbol::Symbol>::new_ident from CodeQL/Pysa",
        detect_imports: PROC_MACRO_BRIDGE_SYMBOL_SYMBOL_NEW_IDENT_GEN_IMPORTS,
        sources: PROC_MACRO_BRIDGE_SYMBOL_SYMBOL_NEW_IDENT_GEN_SOURCES,
        sinks: PROC_MACRO_BRIDGE_SYMBOL_SYMBOL_NEW_IDENT_GEN_SINKS,
        sanitizers: PROC_MACRO_BRIDGE_SYMBOL_SYMBOL_NEW_IDENT_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
