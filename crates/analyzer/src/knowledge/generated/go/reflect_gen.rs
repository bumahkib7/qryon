//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REFLECT_GEN_SOURCES: &[SourceDef] = &[];

static REFLECT_GEN_SINKS: &[SinkDef] = &[];

static REFLECT_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "reflect.Value.UnsafeAddr",
    pattern: SanitizerKind::Function("reflect.Value.UnsafeAddr"),
    sanitizes: "general",
    description: "CodeQL sanitizer: reflect.Value.UnsafeAddr",
}];

static REFLECT_GEN_IMPORTS: &[&str] = &["reflect"];

pub static REFLECT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "reflect_generated",
    description: "Generated profile for reflect from CodeQL/Pysa",
    detect_imports: REFLECT_GEN_IMPORTS,
    sources: REFLECT_GEN_SOURCES,
    sinks: REFLECT_GEN_SINKS,
    sanitizers: REFLECT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
