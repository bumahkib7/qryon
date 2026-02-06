//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static KEY_GEN_SOURCES: &[SourceDef] = &[];

static KEY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "key",
    pattern: SinkKind::FunctionCall("key"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: key (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static KEY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static KEY_GEN_IMPORTS: &[&str] = &["key"];

pub static KEY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "key_generated",
    description: "Generated profile for key from CodeQL/Pysa",
    detect_imports: KEY_GEN_IMPORTS,
    sources: KEY_GEN_SOURCES,
    sinks: KEY_GEN_SINKS,
    sanitizers: KEY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
