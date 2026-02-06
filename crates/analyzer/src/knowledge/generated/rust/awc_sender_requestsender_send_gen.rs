//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AWC_SENDER_REQUESTSENDER_SEND_GEN_SOURCES: &[SourceDef] = &[];

static AWC_SENDER_REQUESTSENDER_SEND_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<awc::sender::RequestSender>::send.Argument[2]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[2] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "<awc::sender::RequestSender>::send.Argument[3]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[3] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static AWC_SENDER_REQUESTSENDER_SEND_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AWC_SENDER_REQUESTSENDER_SEND_GEN_IMPORTS: &[&str] = &["<awc::sender::RequestSender>::send"];

pub static AWC_SENDER_REQUESTSENDER_SEND_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<awc::sender::requestsender>::send_generated",
    description: "Generated profile for <awc::sender::RequestSender>::send from CodeQL/Pysa",
    detect_imports: AWC_SENDER_REQUESTSENDER_SEND_GEN_IMPORTS,
    sources: AWC_SENDER_REQUESTSENDER_SEND_GEN_SOURCES,
    sinks: AWC_SENDER_REQUESTSENDER_SEND_GEN_SINKS,
    sanitizers: AWC_SENDER_REQUESTSENDER_SEND_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
