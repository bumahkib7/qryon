//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HTML_MESSAGE_GEN_SOURCES: &[SourceDef] = &[];

static HTML_MESSAGE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "html_message",
    pattern: SinkKind::FunctionCall("html_message"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: html_message (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static HTML_MESSAGE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HTML_MESSAGE_GEN_IMPORTS: &[&str] = &["html_message"];

pub static HTML_MESSAGE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "html_message_generated",
    description: "Generated profile for html_message from CodeQL/Pysa",
    detect_imports: HTML_MESSAGE_GEN_IMPORTS,
    sources: HTML_MESSAGE_GEN_SOURCES,
    sinks: HTML_MESSAGE_GEN_SINKS,
    sanitizers: HTML_MESSAGE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
