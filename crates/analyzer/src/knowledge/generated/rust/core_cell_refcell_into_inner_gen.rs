//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_CELL_REFCELL_INTO_INNER_GEN_SOURCES: &[SourceDef] = &[];

static CORE_CELL_REFCELL_INTO_INNER_GEN_SINKS: &[SinkDef] = &[];

static CORE_CELL_REFCELL_INTO_INNER_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "<core::cell::RefCell>::into_inner.Argument[self].Field[core::cell::RefCell::value].Field[core::cell::UnsafeCell::value]",
    pattern: SanitizerKind::Function(
        "Argument[self].Field[core::cell::RefCell::value].Field[core::cell::UnsafeCell::value]",
    ),
    sanitizes: "general",
    description: "CodeQL sanitizer: Argument[self].Field[core::cell::RefCell::value].Field[core::cell::UnsafeCell::value]",
}];

static CORE_CELL_REFCELL_INTO_INNER_GEN_IMPORTS: &[&str] = &["<core::cell::RefCell>::into_inner"];

pub static CORE_CELL_REFCELL_INTO_INNER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<core::cell::refcell>::into_inner_generated",
    description: "Generated profile for <core::cell::RefCell>::into_inner from CodeQL/Pysa",
    detect_imports: CORE_CELL_REFCELL_INTO_INNER_GEN_IMPORTS,
    sources: CORE_CELL_REFCELL_INTO_INNER_GEN_SOURCES,
    sinks: CORE_CELL_REFCELL_INTO_INNER_GEN_SINKS,
    sanitizers: CORE_CELL_REFCELL_INTO_INNER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
