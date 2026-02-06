//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static __NAME_GEN_SOURCES: &[SourceDef] = &[];

static __NAME_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "__name",
    pattern: SinkKind::FunctionCall("__name"),
    rule_id: "python/gen-pysa-getattr",
    severity: Severity::Error,
    description: "Pysa sink: __name (kind: GetAttr)",
    cwe: Some("CWE-74"),
}];

static __NAME_GEN_SANITIZERS: &[SanitizerDef] = &[];

static __NAME_GEN_IMPORTS: &[&str] = &["__name"];

pub static __NAME_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "__name_generated",
    description: "Generated profile for __name from CodeQL/Pysa",
    detect_imports: __NAME_GEN_IMPORTS,
    sources: __NAME_GEN_SOURCES,
    sinks: __NAME_GEN_SINKS,
    sanitizers: __NAME_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
