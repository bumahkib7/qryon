//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static BCC_GEN_SOURCES: &[SourceDef] = &[];

static BCC_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "bcc",
    pattern: SinkKind::FunctionCall("bcc"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: bcc (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static BCC_GEN_SANITIZERS: &[SanitizerDef] = &[];

static BCC_GEN_IMPORTS: &[&str] = &["bcc"];

pub static BCC_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "bcc_generated",
    description: "Generated profile for bcc from CodeQL/Pysa",
    detect_imports: BCC_GEN_IMPORTS,
    sources: BCC_GEN_SOURCES,
    sinks: BCC_GEN_SINKS,
    sanitizers: BCC_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
