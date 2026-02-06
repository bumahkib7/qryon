//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MUT_DROP_IN_PLACE_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<*mut>::drop_in_place.Argument[self]",
    pattern: SourceKind::FunctionCall("Argument[self]"),
    taint_label: "user_input",
    description: "CodeQL source: Argument[self] (kind: pointer-invalidate)",
}];

static MUT_DROP_IN_PLACE_GEN_SINKS: &[SinkDef] = &[];

static MUT_DROP_IN_PLACE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MUT_DROP_IN_PLACE_GEN_IMPORTS: &[&str] = &["<*mut>::drop_in_place"];

pub static MUT_DROP_IN_PLACE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<*mut>::drop_in_place_generated",
    description: "Generated profile for <*mut>::drop_in_place from CodeQL/Pysa",
    detect_imports: MUT_DROP_IN_PLACE_GEN_IMPORTS,
    sources: MUT_DROP_IN_PLACE_GEN_SOURCES,
    sinks: MUT_DROP_IN_PLACE_GEN_SINKS,
    sanitizers: MUT_DROP_IN_PLACE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
