//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKEN_GEN_SOURCES: &[SourceDef] = &[];

static TOKEN_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "token",
    pattern: SinkKind::FunctionCall("token"),
    rule_id: "python/gen-pysa-authentication",
    severity: Severity::Error,
    description: "Pysa sink: token (kind: Authentication)",
    cwe: Some("CWE-74"),
}];

static TOKEN_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKEN_GEN_IMPORTS: &[&str] = &["token"];

pub static TOKEN_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "token_generated",
    description: "Generated profile for token from CodeQL/Pysa",
    detect_imports: TOKEN_GEN_IMPORTS,
    sources: TOKEN_GEN_SOURCES,
    sinks: TOKEN_GEN_SINKS,
    sanitizers: TOKEN_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
