//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static URL_GEN_SOURCES: &[SourceDef] = &[];

static URL_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "url",
    pattern: SinkKind::FunctionCall("url"),
    rule_id: "python/gen-pysa-httpclientrequest_uri",
    severity: Severity::Error,
    description: "Pysa sink: url (kind: HTTPClientRequest_URI)",
    cwe: Some("CWE-74"),
}];

static URL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static URL_GEN_IMPORTS: &[&str] = &["url"];

pub static URL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "url_generated",
    description: "Generated profile for url from CodeQL/Pysa",
    detect_imports: URL_GEN_IMPORTS,
    sources: URL_GEN_SOURCES,
    sinks: URL_GEN_SINKS,
    sanitizers: URL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
