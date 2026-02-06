//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REQWEST_BLOCKING_BODY_BODY_BUFFER_GEN_SOURCES: &[SourceDef] = &[];

static REQWEST_BLOCKING_BODY_BODY_BUFFER_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<reqwest::blocking::body::Body>::buffer.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static REQWEST_BLOCKING_BODY_BODY_BUFFER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REQWEST_BLOCKING_BODY_BODY_BUFFER_GEN_IMPORTS: &[&str] =
    &["<reqwest::blocking::body::Body>::buffer"];

pub static REQWEST_BLOCKING_BODY_BODY_BUFFER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<reqwest::blocking::body::body>::buffer_generated",
    description: "Generated profile for <reqwest::blocking::body::Body>::buffer from CodeQL/Pysa",
    detect_imports: REQWEST_BLOCKING_BODY_BODY_BUFFER_GEN_IMPORTS,
    sources: REQWEST_BLOCKING_BODY_BODY_BUFFER_GEN_SOURCES,
    sinks: REQWEST_BLOCKING_BODY_BODY_BUFFER_GEN_SINKS,
    sanitizers: REQWEST_BLOCKING_BODY_BODY_BUFFER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
