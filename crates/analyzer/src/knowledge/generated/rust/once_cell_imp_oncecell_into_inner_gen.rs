//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ONCE_CELL_IMP_ONCECELL_INTO_INNER_GEN_SOURCES: &[SourceDef] = &[];

static ONCE_CELL_IMP_ONCECELL_INTO_INNER_GEN_SINKS: &[SinkDef] = &[];

static ONCE_CELL_IMP_ONCECELL_INTO_INNER_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "<once_cell::imp::OnceCell>::into_inner.Argument[self].Field[once_cell::imp::OnceCell::value].Field[core::cell::UnsafeCell::value]",
    pattern: SanitizerKind::Function(
        "Argument[self].Field[once_cell::imp::OnceCell::value].Field[core::cell::UnsafeCell::value]",
    ),
    sanitizes: "general",
    description: "CodeQL sanitizer: Argument[self].Field[once_cell::imp::OnceCell::value].Field[core::cell::UnsafeCell::value]",
}];

static ONCE_CELL_IMP_ONCECELL_INTO_INNER_GEN_IMPORTS: &[&str] =
    &["<once_cell::imp::OnceCell>::into_inner"];

pub static ONCE_CELL_IMP_ONCECELL_INTO_INNER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<once_cell::imp::oncecell>::into_inner_generated",
    description: "Generated profile for <once_cell::imp::OnceCell>::into_inner from CodeQL/Pysa",
    detect_imports: ONCE_CELL_IMP_ONCECELL_INTO_INNER_GEN_IMPORTS,
    sources: ONCE_CELL_IMP_ONCECELL_INTO_INNER_GEN_SOURCES,
    sinks: ONCE_CELL_IMP_ONCECELL_INTO_INNER_GEN_SINKS,
    sanitizers: ONCE_CELL_IMP_ONCECELL_INTO_INNER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
