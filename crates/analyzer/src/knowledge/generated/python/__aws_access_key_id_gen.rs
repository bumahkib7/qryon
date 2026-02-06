//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static __AWS_ACCESS_KEY_ID_GEN_SOURCES: &[SourceDef] = &[];

static __AWS_ACCESS_KEY_ID_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "__aws_access_key_id",
    pattern: SinkKind::FunctionCall("__aws_access_key_id"),
    rule_id: "python/gen-pysa-authentication",
    severity: Severity::Error,
    description: "Pysa sink: __aws_access_key_id (kind: Authentication)",
    cwe: Some("CWE-74"),
}];

static __AWS_ACCESS_KEY_ID_GEN_SANITIZERS: &[SanitizerDef] = &[];

static __AWS_ACCESS_KEY_ID_GEN_IMPORTS: &[&str] = &["__aws_access_key_id"];

pub static __AWS_ACCESS_KEY_ID_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "__aws_access_key_id_generated",
    description: "Generated profile for __aws_access_key_id from CodeQL/Pysa",
    detect_imports: __AWS_ACCESS_KEY_ID_GEN_IMPORTS,
    sources: __AWS_ACCESS_KEY_ID_GEN_SOURCES,
    sinks: __AWS_ACCESS_KEY_ID_GEN_SINKS,
    sanitizers: __AWS_ACCESS_KEY_ID_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
