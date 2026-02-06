//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PROXY_GEN_SOURCES: &[SourceDef] = &[];

static PROXY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "proxy",
    pattern: SinkKind::FunctionCall("proxy"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: proxy (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static PROXY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PROXY_GEN_IMPORTS: &[&str] = &["proxy"];

pub static PROXY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "proxy_generated",
    description: "Generated profile for proxy from CodeQL/Pysa",
    detect_imports: PROXY_GEN_IMPORTS,
    sources: PROXY_GEN_SOURCES,
    sinks: PROXY_GEN_SINKS,
    sanitizers: PROXY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
