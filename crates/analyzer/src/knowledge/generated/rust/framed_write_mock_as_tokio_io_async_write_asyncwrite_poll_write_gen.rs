//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FRAMED_WRITE_MOCK_AS_TOKIO_IO_ASYNC_WRITE_ASYNCWRITE_POLL_WRITE_GEN_SOURCES: &[SourceDef] =
    &[];

static FRAMED_WRITE_MOCK_AS_TOKIO_IO_ASYNC_WRITE_ASYNCWRITE_POLL_WRITE_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<framed_write::Mock as tokio::io::async_write::AsyncWrite>::poll_write.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[1] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static FRAMED_WRITE_MOCK_AS_TOKIO_IO_ASYNC_WRITE_ASYNCWRITE_POLL_WRITE_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static FRAMED_WRITE_MOCK_AS_TOKIO_IO_ASYNC_WRITE_ASYNCWRITE_POLL_WRITE_GEN_IMPORTS: &[&str] =
    &["<framed_write::Mock as tokio::io::async_write::AsyncWrite>::poll_write"];

pub static FRAMED_WRITE_MOCK_AS_TOKIO_IO_ASYNC_WRITE_ASYNCWRITE_POLL_WRITE_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<framed_write::mock as tokio::io::async_write::asyncwrite>::poll_write_generated",
    description: "Generated profile for <framed_write::Mock as tokio::io::async_write::AsyncWrite>::poll_write from CodeQL/Pysa",
    detect_imports: FRAMED_WRITE_MOCK_AS_TOKIO_IO_ASYNC_WRITE_ASYNCWRITE_POLL_WRITE_GEN_IMPORTS,
    sources: FRAMED_WRITE_MOCK_AS_TOKIO_IO_ASYNC_WRITE_ASYNCWRITE_POLL_WRITE_GEN_SOURCES,
    sinks: FRAMED_WRITE_MOCK_AS_TOKIO_IO_ASYNC_WRITE_ASYNCWRITE_POLL_WRITE_GEN_SINKS,
    sanitizers: FRAMED_WRITE_MOCK_AS_TOKIO_IO_ASYNC_WRITE_ASYNCWRITE_POLL_WRITE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
