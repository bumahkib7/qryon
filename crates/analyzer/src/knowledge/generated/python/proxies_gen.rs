//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PROXIES_GEN_SOURCES: &[SourceDef] = &[];

static PROXIES_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "proxies",
    pattern: SinkKind::FunctionCall("proxies"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: proxies (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static PROXIES_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PROXIES_GEN_IMPORTS: &[&str] = &["proxies"];

pub static PROXIES_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "proxies_generated",
    description: "Generated profile for proxies from CodeQL/Pysa",
    detect_imports: PROXIES_GEN_IMPORTS,
    sources: PROXIES_GEN_SOURCES,
    sinks: PROXIES_GEN_SINKS,
    sanitizers: PROXIES_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
