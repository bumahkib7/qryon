//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ASSUME_INIT_DROP_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<[]>::assume_init_drop.Argument[self]",
    pattern: SourceKind::FunctionCall("Argument[self]"),
    taint_label: "user_input",
    description: "CodeQL source: Argument[self] (kind: pointer-invalidate)",
}];

static ASSUME_INIT_DROP_GEN_SINKS: &[SinkDef] = &[];

static ASSUME_INIT_DROP_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ASSUME_INIT_DROP_GEN_IMPORTS: &[&str] = &["<[]>::assume_init_drop"];

pub static ASSUME_INIT_DROP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<[]>::assume_init_drop_generated",
    description: "Generated profile for <[]>::assume_init_drop from CodeQL/Pysa",
    detect_imports: ASSUME_INIT_DROP_GEN_IMPORTS,
    sources: ASSUME_INIT_DROP_GEN_SOURCES,
    sinks: ASSUME_INIT_DROP_GEN_SINKS,
    sanitizers: ASSUME_INIT_DROP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
