//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AWC_SENDER_SENDCLIENTREQUEST_NEW_GEN_SOURCES: &[SourceDef] = &[];

static AWC_SENDER_SENDCLIENTREQUEST_NEW_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<awc::sender::SendClientRequest>::new.Argument[2]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[2] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static AWC_SENDER_SENDCLIENTREQUEST_NEW_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AWC_SENDER_SENDCLIENTREQUEST_NEW_GEN_IMPORTS: &[&str] =
    &["<awc::sender::SendClientRequest>::new"];

pub static AWC_SENDER_SENDCLIENTREQUEST_NEW_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<awc::sender::sendclientrequest>::new_generated",
    description: "Generated profile for <awc::sender::SendClientRequest>::new from CodeQL/Pysa",
    detect_imports: AWC_SENDER_SENDCLIENTREQUEST_NEW_GEN_IMPORTS,
    sources: AWC_SENDER_SENDCLIENTREQUEST_NEW_GEN_SOURCES,
    sinks: AWC_SENDER_SENDCLIENTREQUEST_NEW_GEN_SINKS,
    sanitizers: AWC_SENDER_SENDCLIENTREQUEST_NEW_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
