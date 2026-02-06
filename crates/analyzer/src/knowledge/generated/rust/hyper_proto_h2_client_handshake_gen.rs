//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_PROTO_H2_CLIENT_HANDSHAKE_GEN_SOURCES: &[SourceDef] = &[];

static HYPER_PROTO_H2_CLIENT_HANDSHAKE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "hyper::proto::h2::client::handshake.Argument[2]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[2] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static HYPER_PROTO_H2_CLIENT_HANDSHAKE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HYPER_PROTO_H2_CLIENT_HANDSHAKE_GEN_IMPORTS: &[&str] =
    &["hyper::proto::h2::client::handshake"];

pub static HYPER_PROTO_H2_CLIENT_HANDSHAKE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "hyper::proto::h2::client::handshake_generated",
    description: "Generated profile for hyper::proto::h2::client::handshake from CodeQL/Pysa",
    detect_imports: HYPER_PROTO_H2_CLIENT_HANDSHAKE_GEN_IMPORTS,
    sources: HYPER_PROTO_H2_CLIENT_HANDSHAKE_GEN_SOURCES,
    sinks: HYPER_PROTO_H2_CLIENT_HANDSHAKE_GEN_SINKS,
    sanitizers: HYPER_PROTO_H2_CLIENT_HANDSHAKE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
