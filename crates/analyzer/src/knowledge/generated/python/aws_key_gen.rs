//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AWS_KEY_GEN_SOURCES: &[SourceDef] = &[];

static AWS_KEY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "aws_key",
    pattern: SinkKind::FunctionCall("aws_key"),
    rule_id: "python/gen-pysa-authentication",
    severity: Severity::Error,
    description: "Pysa sink: aws_key (kind: Authentication)",
    cwe: Some("CWE-74"),
}];

static AWS_KEY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AWS_KEY_GEN_IMPORTS: &[&str] = &["aws_key"];

pub static AWS_KEY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "aws_key_generated",
    description: "Generated profile for aws_key from CodeQL/Pysa",
    detect_imports: AWS_KEY_GEN_IMPORTS,
    sources: AWS_KEY_GEN_SOURCES,
    sinks: AWS_KEY_GEN_SINKS,
    sanitizers: AWS_KEY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
