//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_CELL_LAZY_LAZYCELL_FORCE_MUT_GEN_SOURCES: &[SourceDef] = &[];

static CORE_CELL_LAZY_LAZYCELL_FORCE_MUT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<core::cell::lazy::LazyCell>::force_mut.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static CORE_CELL_LAZY_LAZYCELL_FORCE_MUT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_CELL_LAZY_LAZYCELL_FORCE_MUT_GEN_IMPORTS: &[&str] =
    &["<core::cell::lazy::LazyCell>::force_mut"];

pub static CORE_CELL_LAZY_LAZYCELL_FORCE_MUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<core::cell::lazy::lazycell>::force_mut_generated",
    description: "Generated profile for <core::cell::lazy::LazyCell>::force_mut from CodeQL/Pysa",
    detect_imports: CORE_CELL_LAZY_LAZYCELL_FORCE_MUT_GEN_IMPORTS,
    sources: CORE_CELL_LAZY_LAZYCELL_FORCE_MUT_GEN_SOURCES,
    sinks: CORE_CELL_LAZY_LAZYCELL_FORCE_MUT_GEN_SINKS,
    sanitizers: CORE_CELL_LAZY_LAZYCELL_FORCE_MUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
