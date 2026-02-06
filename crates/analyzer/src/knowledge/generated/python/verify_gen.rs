//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static VERIFY_GEN_SOURCES: &[SourceDef] = &[];

static VERIFY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "verify",
    pattern: SinkKind::FunctionCall("verify"),
    rule_id: "python/gen-pysa-httpclientrequest_metadata",
    severity: Severity::Error,
    description: "Pysa sink: verify (kind: HTTPClientRequest_METADATA)",
    cwe: Some("CWE-74"),
}];

static VERIFY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static VERIFY_GEN_IMPORTS: &[&str] = &["verify"];

pub static VERIFY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "verify_generated",
    description: "Generated profile for verify from CodeQL/Pysa",
    detect_imports: VERIFY_GEN_IMPORTS,
    sources: VERIFY_GEN_SOURCES,
    sinks: VERIFY_GEN_SINKS,
    sanitizers: VERIFY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
