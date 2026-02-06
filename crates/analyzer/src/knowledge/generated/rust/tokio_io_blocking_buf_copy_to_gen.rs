//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_IO_BLOCKING_BUF_COPY_TO_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_IO_BLOCKING_BUF_COPY_TO_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::io::blocking::Buf>::copy_to.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_IO_BLOCKING_BUF_COPY_TO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_IO_BLOCKING_BUF_COPY_TO_GEN_IMPORTS: &[&str] =
    &["<tokio::io::blocking::Buf>::copy_to"];

pub static TOKIO_IO_BLOCKING_BUF_COPY_TO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<tokio::io::blocking::buf>::copy_to_generated",
    description: "Generated profile for <tokio::io::blocking::Buf>::copy_to from CodeQL/Pysa",
    detect_imports: TOKIO_IO_BLOCKING_BUF_COPY_TO_GEN_IMPORTS,
    sources: TOKIO_IO_BLOCKING_BUF_COPY_TO_GEN_SOURCES,
    sinks: TOKIO_IO_BLOCKING_BUF_COPY_TO_GEN_SINKS,
    sanitizers: TOKIO_IO_BLOCKING_BUF_COPY_TO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
