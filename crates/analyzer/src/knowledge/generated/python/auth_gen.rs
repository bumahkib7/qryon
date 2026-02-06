//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AUTH_GEN_SOURCES: &[SourceDef] = &[];

static AUTH_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "auth",
    pattern: SinkKind::FunctionCall("auth"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: auth (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static AUTH_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AUTH_GEN_IMPORTS: &[&str] = &["auth"];

pub static AUTH_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "auth_generated",
    description: "Generated profile for auth from CodeQL/Pysa",
    detect_imports: AUTH_GEN_IMPORTS,
    sources: AUTH_GEN_SOURCES,
    sinks: AUTH_GEN_SINKS,
    sanitizers: AUTH_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
