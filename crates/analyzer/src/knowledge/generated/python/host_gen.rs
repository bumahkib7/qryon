//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HOST_GEN_SOURCES: &[SourceDef] = &[];

static HOST_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "host",
    pattern: SinkKind::FunctionCall("host"),
    rule_id: "python/gen-pysa-httpclientrequest_uri",
    severity: Severity::Error,
    description: "Pysa sink: host (kind: HTTPClientRequest_URI)",
    cwe: Some("CWE-74"),
}];

static HOST_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HOST_GEN_IMPORTS: &[&str] = &["host"];

pub static HOST_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "host_generated",
    description: "Generated profile for host from CodeQL/Pysa",
    detect_imports: HOST_GEN_IMPORTS,
    sources: HOST_GEN_SOURCES,
    sinks: HOST_GEN_SINKS,
    sanitizers: HOST_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
