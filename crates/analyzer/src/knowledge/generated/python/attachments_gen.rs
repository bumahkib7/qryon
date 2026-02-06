//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ATTACHMENTS_GEN_SOURCES: &[SourceDef] = &[];

static ATTACHMENTS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "attachments",
    pattern: SinkKind::FunctionCall("attachments"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: attachments (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static ATTACHMENTS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ATTACHMENTS_GEN_IMPORTS: &[&str] = &["attachments"];

pub static ATTACHMENTS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "attachments_generated",
    description: "Generated profile for attachments from CodeQL/Pysa",
    detect_imports: ATTACHMENTS_GEN_IMPORTS,
    sources: ATTACHMENTS_GEN_SOURCES,
    sinks: ATTACHMENTS_GEN_SINKS,
    sanitizers: ATTACHMENTS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
