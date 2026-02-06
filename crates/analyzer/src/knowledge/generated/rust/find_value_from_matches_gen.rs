//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FIND_VALUE_FROM_MATCHES_GEN_SOURCES: &[SourceDef] = &[];

static FIND_VALUE_FROM_MATCHES_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<find::Value>::from_matches.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static FIND_VALUE_FROM_MATCHES_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FIND_VALUE_FROM_MATCHES_GEN_IMPORTS: &[&str] = &["<find::Value>::from_matches"];

pub static FIND_VALUE_FROM_MATCHES_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<find::value>::from_matches_generated",
    description: "Generated profile for <find::Value>::from_matches from CodeQL/Pysa",
    detect_imports: FIND_VALUE_FROM_MATCHES_GEN_IMPORTS,
    sources: FIND_VALUE_FROM_MATCHES_GEN_SOURCES,
    sinks: FIND_VALUE_FROM_MATCHES_GEN_SINKS,
    sanitizers: FIND_VALUE_FROM_MATCHES_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
