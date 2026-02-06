//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_CELL_UNSAFECELL_GET_MUT_GEN_SOURCES: &[SourceDef] = &[];

static CORE_CELL_UNSAFECELL_GET_MUT_GEN_SINKS: &[SinkDef] = &[];

static CORE_CELL_UNSAFECELL_GET_MUT_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "<core::cell::UnsafeCell>::get_mut.Argument[self].Reference.Field[core::cell::UnsafeCell::value]",
    pattern: SanitizerKind::Function(
        "Argument[self].Reference.Field[core::cell::UnsafeCell::value]",
    ),
    sanitizes: "general",
    description: "CodeQL sanitizer: Argument[self].Reference.Field[core::cell::UnsafeCell::value]",
}];

static CORE_CELL_UNSAFECELL_GET_MUT_GEN_IMPORTS: &[&str] = &["<core::cell::UnsafeCell>::get_mut"];

pub static CORE_CELL_UNSAFECELL_GET_MUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<core::cell::unsafecell>::get_mut_generated",
    description: "Generated profile for <core::cell::UnsafeCell>::get_mut from CodeQL/Pysa",
    detect_imports: CORE_CELL_UNSAFECELL_GET_MUT_GEN_IMPORTS,
    sources: CORE_CELL_UNSAFECELL_GET_MUT_GEN_SOURCES,
    sinks: CORE_CELL_UNSAFECELL_GET_MUT_GEN_SINKS,
    sanitizers: CORE_CELL_UNSAFECELL_GET_MUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
