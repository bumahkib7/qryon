//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AWS_SECRET_GEN_SOURCES: &[SourceDef] = &[];

static AWS_SECRET_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "aws_secret",
    pattern: SinkKind::FunctionCall("aws_secret"),
    rule_id: "python/gen-pysa-authentication",
    severity: Severity::Error,
    description: "Pysa sink: aws_secret (kind: Authentication)",
    cwe: Some("CWE-74"),
}];

static AWS_SECRET_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AWS_SECRET_GEN_IMPORTS: &[&str] = &["aws_secret"];

pub static AWS_SECRET_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "aws_secret_generated",
    description: "Generated profile for aws_secret from CodeQL/Pysa",
    detect_imports: AWS_SECRET_GEN_IMPORTS,
    sources: AWS_SECRET_GEN_SOURCES,
    sinks: AWS_SECRET_GEN_SINKS,
    sanitizers: AWS_SECRET_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
