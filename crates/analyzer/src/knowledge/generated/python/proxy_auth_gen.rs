//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PROXY_AUTH_GEN_SOURCES: &[SourceDef] = &[];

static PROXY_AUTH_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "proxy_auth",
    pattern: SinkKind::FunctionCall("proxy_auth"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: proxy_auth (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static PROXY_AUTH_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PROXY_AUTH_GEN_IMPORTS: &[&str] = &["proxy_auth"];

pub static PROXY_AUTH_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "proxy_auth_generated",
    description: "Generated profile for proxy_auth from CodeQL/Pysa",
    detect_imports: PROXY_AUTH_GEN_IMPORTS,
    sources: PROXY_AUTH_GEN_SOURCES,
    sinks: PROXY_AUTH_GEN_SINKS,
    sanitizers: PROXY_AUTH_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
