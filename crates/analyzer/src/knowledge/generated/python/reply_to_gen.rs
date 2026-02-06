//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REPLY_TO_GEN_SOURCES: &[SourceDef] = &[];

static REPLY_TO_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "reply_to",
    pattern: SinkKind::FunctionCall("reply_to"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: reply_to (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static REPLY_TO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REPLY_TO_GEN_IMPORTS: &[&str] = &["reply_to"];

pub static REPLY_TO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "reply_to_generated",
    description: "Generated profile for reply_to from CodeQL/Pysa",
    detect_imports: REPLY_TO_GEN_IMPORTS,
    sources: REPLY_TO_GEN_SOURCES,
    sinks: REPLY_TO_GEN_SINKS,
    sanitizers: REPLY_TO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
