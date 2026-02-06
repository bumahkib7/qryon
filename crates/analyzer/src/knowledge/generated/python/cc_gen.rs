//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CC_GEN_SOURCES: &[SourceDef] = &[];

static CC_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "cc",
    pattern: SinkKind::FunctionCall("cc"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: cc (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static CC_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CC_GEN_IMPORTS: &[&str] = &["cc"];

pub static CC_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "cc_generated",
    description: "Generated profile for cc from CodeQL/Pysa",
    detect_imports: CC_GEN_IMPORTS,
    sources: CC_GEN_SOURCES,
    sinks: CC_GEN_SINKS,
    sanitizers: CC_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
