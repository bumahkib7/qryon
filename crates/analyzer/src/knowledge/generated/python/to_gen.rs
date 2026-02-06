//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TO_GEN_SOURCES: &[SourceDef] = &[];

static TO_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "to",
    pattern: SinkKind::FunctionCall("to"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: to (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static TO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TO_GEN_IMPORTS: &[&str] = &["to"];

pub static TO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "to_generated",
    description: "Generated profile for to from CodeQL/Pysa",
    detect_imports: TO_GEN_IMPORTS,
    sources: TO_GEN_SOURCES,
    sinks: TO_GEN_SINKS,
    sanitizers: TO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
