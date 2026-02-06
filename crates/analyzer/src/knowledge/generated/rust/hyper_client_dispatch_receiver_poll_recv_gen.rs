//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_CLIENT_DISPATCH_RECEIVER_POLL_RECV_GEN_SOURCES: &[SourceDef] = &[];

static HYPER_CLIENT_DISPATCH_RECEIVER_POLL_RECV_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<hyper::client::dispatch::Receiver>::poll_recv.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static HYPER_CLIENT_DISPATCH_RECEIVER_POLL_RECV_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HYPER_CLIENT_DISPATCH_RECEIVER_POLL_RECV_GEN_IMPORTS: &[&str] =
    &["<hyper::client::dispatch::Receiver>::poll_recv"];

pub static HYPER_CLIENT_DISPATCH_RECEIVER_POLL_RECV_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<hyper::client::dispatch::receiver>::poll_recv_generated",
        description: "Generated profile for <hyper::client::dispatch::Receiver>::poll_recv from CodeQL/Pysa",
        detect_imports: HYPER_CLIENT_DISPATCH_RECEIVER_POLL_RECV_GEN_IMPORTS,
        sources: HYPER_CLIENT_DISPATCH_RECEIVER_POLL_RECV_GEN_SOURCES,
        sinks: HYPER_CLIENT_DISPATCH_RECEIVER_POLL_RECV_GEN_SINKS,
        sanitizers: HYPER_CLIENT_DISPATCH_RECEIVER_POLL_RECV_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
