//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CONTENT_GEN_SOURCES: &[SourceDef] = &[];

static CONTENT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "content",
    pattern: SinkKind::FunctionCall("content"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: content (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static CONTENT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CONTENT_GEN_IMPORTS: &[&str] = &["content"];

pub static CONTENT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "content_generated",
    description: "Generated profile for content from CodeQL/Pysa",
    detect_imports: CONTENT_GEN_IMPORTS,
    sources: CONTENT_GEN_SOURCES,
    sinks: CONTENT_GEN_SINKS,
    sanitizers: CONTENT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
