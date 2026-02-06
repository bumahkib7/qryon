//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AWC_CLIENT_H2PROTO_SEND_REQUEST_GEN_SOURCES: &[SourceDef] = &[];

static AWC_CLIENT_H2PROTO_SEND_REQUEST_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "awc::client::h2proto::send_request.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[1] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static AWC_CLIENT_H2PROTO_SEND_REQUEST_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AWC_CLIENT_H2PROTO_SEND_REQUEST_GEN_IMPORTS: &[&str] =
    &["awc::client::h2proto::send_request"];

pub static AWC_CLIENT_H2PROTO_SEND_REQUEST_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "awc::client::h2proto::send_request_generated",
    description: "Generated profile for awc::client::h2proto::send_request from CodeQL/Pysa",
    detect_imports: AWC_CLIENT_H2PROTO_SEND_REQUEST_GEN_IMPORTS,
    sources: AWC_CLIENT_H2PROTO_SEND_REQUEST_GEN_SOURCES,
    sinks: AWC_CLIENT_H2PROTO_SEND_REQUEST_GEN_SINKS,
    sanitizers: AWC_CLIENT_H2PROTO_SEND_REQUEST_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
