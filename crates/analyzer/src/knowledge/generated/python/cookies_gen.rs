//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static COOKIES_GEN_SOURCES: &[SourceDef] = &[];

static COOKIES_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "cookies",
    pattern: SinkKind::FunctionCall("cookies"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: cookies (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static COOKIES_GEN_SANITIZERS: &[SanitizerDef] = &[];

static COOKIES_GEN_IMPORTS: &[&str] = &["cookies"];

pub static COOKIES_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "cookies_generated",
    description: "Generated profile for cookies from CodeQL/Pysa",
    detect_imports: COOKIES_GEN_IMPORTS,
    sources: COOKIES_GEN_SOURCES,
    sinks: COOKIES_GEN_SINKS,
    sanitizers: COOKIES_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
