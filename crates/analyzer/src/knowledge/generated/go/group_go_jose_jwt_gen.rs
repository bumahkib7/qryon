//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_GO_JOSE_JWT_GEN_SOURCES: &[SourceDef] = &[];

static GROUP_GO_JOSE_JWT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "group:go-jose/jwt.JSONWebToken.UnsafeClaimsWithoutVerification",
    pattern: SinkKind::FunctionCall(
        "group:go-jose/jwt.JSONWebToken.UnsafeClaimsWithoutVerification",
    ),
    rule_id: "go/gen-manual",
    severity: Severity::Error,
    description: "CodeQL sink: group:go-jose/jwt.JSONWebToken.UnsafeClaimsWithoutVerification (kind: manual)",
    cwe: Some("CWE-74"),
}];

static GROUP_GO_JOSE_JWT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_GO_JOSE_JWT_GEN_IMPORTS: &[&str] = &["group:go-jose/jwt"];

pub static GROUP_GO_JOSE_JWT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:go_jose_jwt_generated",
    description: "Generated profile for group:go-jose/jwt from CodeQL/Pysa",
    detect_imports: GROUP_GO_JOSE_JWT_GEN_IMPORTS,
    sources: GROUP_GO_JOSE_JWT_GEN_SOURCES,
    sinks: GROUP_GO_JOSE_JWT_GEN_SINKS,
    sanitizers: GROUP_GO_JOSE_JWT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
