//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static RECIPIENT_LIST_GEN_SOURCES: &[SourceDef] = &[];

static RECIPIENT_LIST_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "recipient_list",
    pattern: SinkKind::FunctionCall("recipient_list"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: recipient_list (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static RECIPIENT_LIST_GEN_SANITIZERS: &[SanitizerDef] = &[];

static RECIPIENT_LIST_GEN_IMPORTS: &[&str] = &["recipient_list"];

pub static RECIPIENT_LIST_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "recipient_list_generated",
    description: "Generated profile for recipient_list from CodeQL/Pysa",
    detect_imports: RECIPIENT_LIST_GEN_IMPORTS,
    sources: RECIPIENT_LIST_GEN_SOURCES,
    sinks: RECIPIENT_LIST_GEN_SINKS,
    sanitizers: RECIPIENT_LIST_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
