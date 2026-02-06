//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TO_ADDRS_GEN_SOURCES: &[SourceDef] = &[];

static TO_ADDRS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "to_addrs",
    pattern: SinkKind::FunctionCall("to_addrs"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: to_addrs (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static TO_ADDRS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TO_ADDRS_GEN_IMPORTS: &[&str] = &["to_addrs"];

pub static TO_ADDRS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "to_addrs_generated",
    description: "Generated profile for to_addrs from CodeQL/Pysa",
    detect_imports: TO_ADDRS_GEN_IMPORTS,
    sources: TO_ADDRS_GEN_SOURCES,
    sinks: TO_ADDRS_GEN_SINKS,
    sanitizers: TO_ADDRS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
