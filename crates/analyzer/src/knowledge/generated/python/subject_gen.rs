//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SUBJECT_GEN_SOURCES: &[SourceDef] = &[];

static SUBJECT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "subject",
    pattern: SinkKind::FunctionCall("subject"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: subject (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static SUBJECT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SUBJECT_GEN_IMPORTS: &[&str] = &["subject"];

pub static SUBJECT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "subject_generated",
    description: "Generated profile for subject from CodeQL/Pysa",
    detect_imports: SUBJECT_GEN_IMPORTS,
    sources: SUBJECT_GEN_SOURCES,
    sinks: SUBJECT_GEN_SINKS,
    sanitizers: SUBJECT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
