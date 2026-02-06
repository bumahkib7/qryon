//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_BOXED_BOX_TRY_NEW_UNINIT_SLICE_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_BOXED_BOX_TRY_NEW_UNINIT_SLICE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<alloc::boxed::Box>::try_new_uninit_slice.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ALLOC_BOXED_BOX_TRY_NEW_UNINIT_SLICE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOC_BOXED_BOX_TRY_NEW_UNINIT_SLICE_GEN_IMPORTS: &[&str] =
    &["<alloc::boxed::Box>::try_new_uninit_slice"];

pub static ALLOC_BOXED_BOX_TRY_NEW_UNINIT_SLICE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<alloc::boxed::box>::try_new_uninit_slice_generated",
    description: "Generated profile for <alloc::boxed::Box>::try_new_uninit_slice from CodeQL/Pysa",
    detect_imports: ALLOC_BOXED_BOX_TRY_NEW_UNINIT_SLICE_GEN_IMPORTS,
    sources: ALLOC_BOXED_BOX_TRY_NEW_UNINIT_SLICE_GEN_SOURCES,
    sinks: ALLOC_BOXED_BOX_TRY_NEW_UNINIT_SLICE_GEN_SINKS,
    sanitizers: ALLOC_BOXED_BOX_TRY_NEW_UNINIT_SLICE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
