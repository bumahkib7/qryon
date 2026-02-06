//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static VALUE_GEN_SOURCES: &[SourceDef] = &[];

static VALUE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "value",
    pattern: SinkKind::FunctionCall("value"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: value (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static VALUE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static VALUE_GEN_IMPORTS: &[&str] = &["value"];

pub static VALUE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "value_generated",
    description: "Generated profile for value from CodeQL/Pysa",
    detect_imports: VALUE_GEN_IMPORTS,
    sources: VALUE_GEN_SOURCES,
    sinks: VALUE_GEN_SINKS,
    sanitizers: VALUE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
