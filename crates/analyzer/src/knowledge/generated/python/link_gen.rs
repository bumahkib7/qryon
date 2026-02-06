//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LINK_GEN_SOURCES: &[SourceDef] = &[];

static LINK_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "link",
    pattern: SinkKind::FunctionCall("link"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: link (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static LINK_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LINK_GEN_IMPORTS: &[&str] = &["link"];

pub static LINK_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "link_generated",
    description: "Generated profile for link from CodeQL/Pysa",
    detect_imports: LINK_GEN_IMPORTS,
    sources: LINK_GEN_SOURCES,
    sinks: LINK_GEN_SINKS,
    sanitizers: LINK_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
