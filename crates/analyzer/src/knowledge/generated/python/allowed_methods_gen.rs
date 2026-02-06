//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOWED_METHODS_GEN_SOURCES: &[SourceDef] = &[];

static ALLOWED_METHODS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "allowed_methods",
    pattern: SinkKind::FunctionCall("allowed_methods"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: allowed_methods (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static ALLOWED_METHODS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ALLOWED_METHODS_GEN_IMPORTS: &[&str] = &["allowed_methods"];

pub static ALLOWED_METHODS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "allowed_methods_generated",
    description: "Generated profile for allowed_methods from CodeQL/Pysa",
    detect_imports: ALLOWED_METHODS_GEN_IMPORTS,
    sources: ALLOWED_METHODS_GEN_SOURCES,
    sinks: ALLOWED_METHODS_GEN_SINKS,
    sanitizers: ALLOWED_METHODS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
