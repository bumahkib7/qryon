//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FROM_EMAIL_GEN_SOURCES: &[SourceDef] = &[];

static FROM_EMAIL_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "from_email",
    pattern: SinkKind::FunctionCall("from_email"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: from_email (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static FROM_EMAIL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FROM_EMAIL_GEN_IMPORTS: &[&str] = &["from_email"];

pub static FROM_EMAIL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "from_email_generated",
    description: "Generated profile for from_email from CodeQL/Pysa",
    detect_imports: FROM_EMAIL_GEN_IMPORTS,
    sources: FROM_EMAIL_GEN_SOURCES,
    sinks: FROM_EMAIL_GEN_SINKS,
    sanitizers: FROM_EMAIL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
