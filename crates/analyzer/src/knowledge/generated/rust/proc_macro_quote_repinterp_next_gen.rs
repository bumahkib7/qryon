//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PROC_MACRO_QUOTE_REPINTERP_NEXT_GEN_SOURCES: &[SourceDef] = &[];

static PROC_MACRO_QUOTE_REPINTERP_NEXT_GEN_SINKS: &[SinkDef] = &[];

static PROC_MACRO_QUOTE_REPINTERP_NEXT_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "<proc_macro::quote::RepInterp>::next.Argument[self].Field[proc_macro::quote::RepInterp(0)]",
    pattern: SanitizerKind::Function("Argument[self].Field[proc_macro::quote::RepInterp(0)]"),
    sanitizes: "general",
    description: "CodeQL sanitizer: Argument[self].Field[proc_macro::quote::RepInterp(0)]",
}];

static PROC_MACRO_QUOTE_REPINTERP_NEXT_GEN_IMPORTS: &[&str] =
    &["<proc_macro::quote::RepInterp>::next"];

pub static PROC_MACRO_QUOTE_REPINTERP_NEXT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<proc_macro::quote::repinterp>::next_generated",
    description: "Generated profile for <proc_macro::quote::RepInterp>::next from CodeQL/Pysa",
    detect_imports: PROC_MACRO_QUOTE_REPINTERP_NEXT_GEN_IMPORTS,
    sources: PROC_MACRO_QUOTE_REPINTERP_NEXT_GEN_SOURCES,
    sinks: PROC_MACRO_QUOTE_REPINTERP_NEXT_GEN_SINKS,
    sanitizers: PROC_MACRO_QUOTE_REPINTERP_NEXT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
