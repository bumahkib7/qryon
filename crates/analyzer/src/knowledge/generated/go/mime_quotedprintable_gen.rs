//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MIME_QUOTEDPRINTABLE_GEN_SOURCES: &[SourceDef] = &[];

static MIME_QUOTEDPRINTABLE_GEN_SINKS: &[SinkDef] = &[];

static MIME_QUOTEDPRINTABLE_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "mime/quotedprintable.NewReader",
    pattern: SanitizerKind::Function("mime/quotedprintable..NewReader"),
    sanitizes: "general",
    description: "CodeQL sanitizer: mime/quotedprintable..NewReader",
}];

static MIME_QUOTEDPRINTABLE_GEN_IMPORTS: &[&str] = &["mime/quotedprintable"];

pub static MIME_QUOTEDPRINTABLE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mime_quotedprintable_generated",
    description: "Generated profile for mime/quotedprintable from CodeQL/Pysa",
    detect_imports: MIME_QUOTEDPRINTABLE_GEN_IMPORTS,
    sources: MIME_QUOTEDPRINTABLE_GEN_SOURCES,
    sinks: MIME_QUOTEDPRINTABLE_GEN_SINKS,
    sanitizers: MIME_QUOTEDPRINTABLE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
