//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static NODE_CORE_GEN_SOURCES: &[SourceDef] = &[];

static NODE_CORE_GEN_SINKS: &[SinkDef] = &[];

static NODE_CORE_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "path.Clean",
    pattern: SanitizerKind::Function("path..Clean"),
    sanitizes: "path",
    description: "CodeQL sanitizer: path..Clean",
}];

static NODE_CORE_GEN_IMPORTS: &[&str] = &["path"];

pub static NODE_CORE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "node_core_generated",
    description: "Generated profile for path from CodeQL/Pysa",
    detect_imports: NODE_CORE_GEN_IMPORTS,
    sources: NODE_CORE_GEN_SOURCES,
    sinks: NODE_CORE_GEN_SINKS,
    sanitizers: NODE_CORE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
