//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_SYNC_ARC_MAKE_MUT_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_SYNC_ARC_MAKE_MUT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<alloc::sync::Arc>::make_mut.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static ALLOC_SYNC_ARC_MAKE_MUT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOC_SYNC_ARC_MAKE_MUT_GEN_IMPORTS: &[&str] = &["<alloc::sync::Arc>::make_mut"];

pub static ALLOC_SYNC_ARC_MAKE_MUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<alloc::sync::arc>::make_mut_generated",
    description: "Generated profile for <alloc::sync::Arc>::make_mut from CodeQL/Pysa",
    detect_imports: ALLOC_SYNC_ARC_MAKE_MUT_GEN_IMPORTS,
    sources: ALLOC_SYNC_ARC_MAKE_MUT_GEN_SOURCES,
    sinks: ALLOC_SYNC_ARC_MAKE_MUT_GEN_SINKS,
    sanitizers: ALLOC_SYNC_ARC_MAKE_MUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
