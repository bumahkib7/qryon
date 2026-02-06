//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MSG_GEN_SOURCES: &[SourceDef] = &[];

static MSG_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "msg",
    pattern: SinkKind::FunctionCall("msg"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: msg (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static MSG_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MSG_GEN_IMPORTS: &[&str] = &["msg"];

pub static MSG_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "msg_generated",
    description: "Generated profile for msg from CodeQL/Pysa",
    detect_imports: MSG_GEN_IMPORTS,
    sources: MSG_GEN_SOURCES,
    sinks: MSG_GEN_SINKS,
    sanitizers: MSG_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
