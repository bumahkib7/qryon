//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TEXT_GEN_SOURCES: &[SourceDef] = &[];

static TEXT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "text",
    pattern: SinkKind::FunctionCall("text"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: text (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static TEXT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TEXT_GEN_IMPORTS: &[&str] = &["text"];

pub static TEXT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "text_generated",
    description: "Generated profile for text from CodeQL/Pysa",
    detect_imports: TEXT_GEN_IMPORTS,
    sources: TEXT_GEN_SOURCES,
    sinks: TEXT_GEN_SINKS,
    sanitizers: TEXT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
