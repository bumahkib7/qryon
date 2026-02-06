//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static RESOURCE_GEN_SOURCES: &[SourceDef] = &[];

static RESOURCE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "resource",
    pattern: SinkKind::FunctionCall("resource"),
    rule_id: "python/gen-pysa-filecontentdeserializationsink",
    severity: Severity::Error,
    description: "Pysa sink: resource (kind: FileContentDeserializationSink)",
    cwe: Some("CWE-74"),
}];

static RESOURCE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static RESOURCE_GEN_IMPORTS: &[&str] = &["resource"];

pub static RESOURCE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "resource_generated",
    description: "Generated profile for resource from CodeQL/Pysa",
    detect_imports: RESOURCE_GEN_IMPORTS,
    sources: RESOURCE_GEN_SOURCES,
    sinks: RESOURCE_GEN_SINKS,
    sanitizers: RESOURCE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
