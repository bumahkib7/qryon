//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AWC_REQUEST_CLIENTREQUEST_SEND_GEN_SOURCES: &[SourceDef] = &[];

static AWC_REQUEST_CLIENTREQUEST_SEND_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<awc::request::ClientRequest>::send.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static AWC_REQUEST_CLIENTREQUEST_SEND_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AWC_REQUEST_CLIENTREQUEST_SEND_GEN_IMPORTS: &[&str] =
    &["<awc::request::ClientRequest>::send"];

pub static AWC_REQUEST_CLIENTREQUEST_SEND_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<awc::request::clientrequest>::send_generated",
    description: "Generated profile for <awc::request::ClientRequest>::send from CodeQL/Pysa",
    detect_imports: AWC_REQUEST_CLIENTREQUEST_SEND_GEN_IMPORTS,
    sources: AWC_REQUEST_CLIENTREQUEST_SEND_GEN_SOURCES,
    sinks: AWC_REQUEST_CLIENTREQUEST_SEND_GEN_SINKS,
    sanitizers: AWC_REQUEST_CLIENTREQUEST_SEND_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
