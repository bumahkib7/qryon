//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static IO_INSPECT_SMALLREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SOURCES:
    &[SourceDef] = &[];

static IO_INSPECT_SMALLREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<io_inspect::SmallReader as tokio::io::async_read::AsyncRead>::poll_read.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[1] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static IO_INSPECT_SMALLREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static IO_INSPECT_SMALLREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_IMPORTS: &[&str] =
    &["<io_inspect::SmallReader as tokio::io::async_read::AsyncRead>::poll_read"];

pub static IO_INSPECT_SMALLREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<io_inspect::smallreader as tokio::io::async_read::asyncread>::poll_read_generated",
    description: "Generated profile for <io_inspect::SmallReader as tokio::io::async_read::AsyncRead>::poll_read from CodeQL/Pysa",
    detect_imports: IO_INSPECT_SMALLREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_IMPORTS,
    sources: IO_INSPECT_SMALLREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SOURCES,
    sinks: IO_INSPECT_SMALLREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SINKS,
    sanitizers: IO_INSPECT_SMALLREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
