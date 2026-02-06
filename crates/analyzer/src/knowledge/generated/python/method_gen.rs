//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static METHOD_GEN_SOURCES: &[SourceDef] = &[];

static METHOD_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "method",
    pattern: SinkKind::FunctionCall("method"),
    rule_id: "python/gen-pysa-returnedtouser",
    severity: Severity::Error,
    description: "Pysa sink: method (kind: ReturnedToUser)",
    cwe: Some("CWE-74"),
}];

static METHOD_GEN_SANITIZERS: &[SanitizerDef] = &[];

static METHOD_GEN_IMPORTS: &[&str] = &["method"];

pub static METHOD_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "method_generated",
    description: "Generated profile for method from CodeQL/Pysa",
    detect_imports: METHOD_GEN_IMPORTS,
    sources: METHOD_GEN_SOURCES,
    sinks: METHOD_GEN_SINKS,
    sanitizers: METHOD_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
