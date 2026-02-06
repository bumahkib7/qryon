//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PROXY_HEADERS_GEN_SOURCES: &[SourceDef] = &[];

static PROXY_HEADERS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "proxy_headers",
    pattern: SinkKind::FunctionCall("proxy_headers"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: proxy_headers (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static PROXY_HEADERS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PROXY_HEADERS_GEN_IMPORTS: &[&str] = &["proxy_headers"];

pub static PROXY_HEADERS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "proxy_headers_generated",
    description: "Generated profile for proxy_headers from CodeQL/Pysa",
    detect_imports: PROXY_HEADERS_GEN_IMPORTS,
    sources: PROXY_HEADERS_GEN_SOURCES,
    sinks: PROXY_HEADERS_GEN_SINKS,
    sanitizers: PROXY_HEADERS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
