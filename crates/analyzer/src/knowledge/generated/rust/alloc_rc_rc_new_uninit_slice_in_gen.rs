//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_RC_RC_NEW_UNINIT_SLICE_IN_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_RC_RC_NEW_UNINIT_SLICE_IN_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<alloc::rc::Rc>::new_uninit_slice_in.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ALLOC_RC_RC_NEW_UNINIT_SLICE_IN_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOC_RC_RC_NEW_UNINIT_SLICE_IN_GEN_IMPORTS: &[&str] =
    &["<alloc::rc::Rc>::new_uninit_slice_in"];

pub static ALLOC_RC_RC_NEW_UNINIT_SLICE_IN_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<alloc::rc::rc>::new_uninit_slice_in_generated",
    description: "Generated profile for <alloc::rc::Rc>::new_uninit_slice_in from CodeQL/Pysa",
    detect_imports: ALLOC_RC_RC_NEW_UNINIT_SLICE_IN_GEN_IMPORTS,
    sources: ALLOC_RC_RC_NEW_UNINIT_SLICE_IN_GEN_SOURCES,
    sinks: ALLOC_RC_RC_NEW_UNINIT_SLICE_IN_GEN_SINKS,
    sanitizers: ALLOC_RC_RC_NEW_UNINIT_SLICE_IN_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
