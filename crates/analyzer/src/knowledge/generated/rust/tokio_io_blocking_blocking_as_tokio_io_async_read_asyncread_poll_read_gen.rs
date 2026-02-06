//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_IO_BLOCKING_BLOCKING_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SOURCES:
    &[SourceDef] = &[];

static TOKIO_IO_BLOCKING_BLOCKING_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<tokio::io::blocking::Blocking as tokio::io::async_read::AsyncRead>::poll_read.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[1] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_IO_BLOCKING_BLOCKING_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static TOKIO_IO_BLOCKING_BLOCKING_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_IMPORTS:
    &[&str] = &["<tokio::io::blocking::Blocking as tokio::io::async_read::AsyncRead>::poll_read"];

pub static TOKIO_IO_BLOCKING_BLOCKING_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<tokio::io::blocking::blocking as tokio::io::async_read::asyncread>::poll_read_generated",
    description: "Generated profile for <tokio::io::blocking::Blocking as tokio::io::async_read::AsyncRead>::poll_read from CodeQL/Pysa",
    detect_imports:
        TOKIO_IO_BLOCKING_BLOCKING_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_IMPORTS,
    sources: TOKIO_IO_BLOCKING_BLOCKING_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SOURCES,
    sinks: TOKIO_IO_BLOCKING_BLOCKING_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SINKS,
    sanitizers:
        TOKIO_IO_BLOCKING_BLOCKING_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
