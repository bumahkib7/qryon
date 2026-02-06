//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AWS_ACCESS_KEY_ID_GEN_SOURCES: &[SourceDef] = &[];

static AWS_ACCESS_KEY_ID_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "aws_access_key_id",
    pattern: SinkKind::FunctionCall("aws_access_key_id"),
    rule_id: "python/gen-pysa-authentication",
    severity: Severity::Error,
    description: "Pysa sink: aws_access_key_id (kind: Authentication)",
    cwe: Some("CWE-74"),
}];

static AWS_ACCESS_KEY_ID_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AWS_ACCESS_KEY_ID_GEN_IMPORTS: &[&str] = &["aws_access_key_id"];

pub static AWS_ACCESS_KEY_ID_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "aws_access_key_id_generated",
    description: "Generated profile for aws_access_key_id from CodeQL/Pysa",
    detect_imports: AWS_ACCESS_KEY_ID_GEN_IMPORTS,
    sources: AWS_ACCESS_KEY_ID_GEN_SOURCES,
    sinks: AWS_ACCESS_KEY_ID_GEN_SINKS,
    sanitizers: AWS_ACCESS_KEY_ID_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
