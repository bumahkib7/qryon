//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HEADERS_GEN_SOURCES: &[SourceDef] = &[];

static HEADERS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "headers",
    pattern: SinkKind::FunctionCall("headers"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: headers (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static HEADERS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HEADERS_GEN_IMPORTS: &[&str] = &["headers"];

pub static HEADERS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "headers_generated",
    description: "Generated profile for headers from CodeQL/Pysa",
    detect_imports: HEADERS_GEN_IMPORTS,
    sources: HEADERS_GEN_SOURCES,
    sinks: HEADERS_GEN_SINKS,
    sanitizers: HEADERS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
