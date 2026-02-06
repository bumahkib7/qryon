//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FROM_ADDR_GEN_SOURCES: &[SourceDef] = &[];

static FROM_ADDR_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "from_addr",
    pattern: SinkKind::FunctionCall("from_addr"),
    rule_id: "python/gen-pysa-emailsend",
    severity: Severity::Error,
    description: "Pysa sink: from_addr (kind: EmailSend)",
    cwe: Some("CWE-74"),
}];

static FROM_ADDR_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FROM_ADDR_GEN_IMPORTS: &[&str] = &["from_addr"];

pub static FROM_ADDR_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "from_addr_generated",
    description: "Generated profile for from_addr from CodeQL/Pysa",
    detect_imports: FROM_ADDR_GEN_IMPORTS,
    sources: FROM_ADDR_GEN_SOURCES,
    sinks: FROM_ADDR_GEN_SINKS,
    sanitizers: FROM_ADDR_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
