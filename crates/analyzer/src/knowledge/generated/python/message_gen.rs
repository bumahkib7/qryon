//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MESSAGE_GEN_SOURCES: &[SourceDef] = &[];

static MESSAGE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "message",
    pattern: SinkKind::FunctionCall("message"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: message (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static MESSAGE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MESSAGE_GEN_IMPORTS: &[&str] = &["message"];

pub static MESSAGE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "message_generated",
    description: "Generated profile for message from CodeQL/Pysa",
    detect_imports: MESSAGE_GEN_IMPORTS,
    sources: MESSAGE_GEN_SOURCES,
    sinks: MESSAGE_GEN_SINKS,
    sanitizers: MESSAGE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
