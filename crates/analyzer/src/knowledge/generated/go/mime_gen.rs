//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MIME_GEN_SOURCES: &[SourceDef] = &[];

static MIME_GEN_SINKS: &[SinkDef] = &[];

static MIME_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "mime.WordEncoder.Encode",
    pattern: SanitizerKind::Function("mime.WordEncoder.Encode"),
    sanitizes: "general",
    description: "CodeQL sanitizer: mime.WordEncoder.Encode",
}];

static MIME_GEN_IMPORTS: &[&str] = &["mime"];

pub static MIME_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mime_generated",
    description: "Generated profile for mime from CodeQL/Pysa",
    detect_imports: MIME_GEN_IMPORTS,
    sources: MIME_GEN_SOURCES,
    sinks: MIME_GEN_SINKS,
    sanitizers: MIME_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
