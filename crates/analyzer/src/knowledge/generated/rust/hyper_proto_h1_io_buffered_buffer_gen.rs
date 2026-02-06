//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_PROTO_H1_IO_BUFFERED_BUFFER_GEN_SOURCES: &[SourceDef] = &[];

static HYPER_PROTO_H1_IO_BUFFERED_BUFFER_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<hyper::proto::h1::io::Buffered>::buffer.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static HYPER_PROTO_H1_IO_BUFFERED_BUFFER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HYPER_PROTO_H1_IO_BUFFERED_BUFFER_GEN_IMPORTS: &[&str] =
    &["<hyper::proto::h1::io::Buffered>::buffer"];

pub static HYPER_PROTO_H1_IO_BUFFERED_BUFFER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<hyper::proto::h1::io::buffered>::buffer_generated",
    description: "Generated profile for <hyper::proto::h1::io::Buffered>::buffer from CodeQL/Pysa",
    detect_imports: HYPER_PROTO_H1_IO_BUFFERED_BUFFER_GEN_IMPORTS,
    sources: HYPER_PROTO_H1_IO_BUFFERED_BUFFER_GEN_SOURCES,
    sinks: HYPER_PROTO_H1_IO_BUFFERED_BUFFER_GEN_SINKS,
    sanitizers: HYPER_PROTO_H1_IO_BUFFERED_BUFFER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
