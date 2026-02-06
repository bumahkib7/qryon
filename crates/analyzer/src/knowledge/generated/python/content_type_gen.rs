//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CONTENT_TYPE_GEN_SOURCES: &[SourceDef] = &[];

static CONTENT_TYPE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "content_type",
    pattern: SinkKind::FunctionCall("content_type"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: content_type (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static CONTENT_TYPE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CONTENT_TYPE_GEN_IMPORTS: &[&str] = &["content_type"];

pub static CONTENT_TYPE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "content_type_generated",
    description: "Generated profile for content_type from CodeQL/Pysa",
    detect_imports: CONTENT_TYPE_GEN_IMPORTS,
    sources: CONTENT_TYPE_GEN_SOURCES,
    sinks: CONTENT_TYPE_GEN_SINKS,
    sanitizers: CONTENT_TYPE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
