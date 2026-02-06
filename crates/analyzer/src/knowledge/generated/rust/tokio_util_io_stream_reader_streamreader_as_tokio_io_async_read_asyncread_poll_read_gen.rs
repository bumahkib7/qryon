//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_UTIL_IO_STREAM_READER_STREAMREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SOURCES: &[SourceDef] = &[
];

static TOKIO_UTIL_IO_STREAM_READER_STREAMREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<tokio_util::io::stream_reader::StreamReader as tokio::io::async_read::AsyncRead>::poll_read.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[1] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static TOKIO_UTIL_IO_STREAM_READER_STREAMREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static TOKIO_UTIL_IO_STREAM_READER_STREAMREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_IMPORTS: &[&str] = &[
    "<tokio_util::io::stream_reader::StreamReader as tokio::io::async_read::AsyncRead>::poll_read",
];

pub static TOKIO_UTIL_IO_STREAM_READER_STREAMREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<tokio_util::io::stream_reader::streamreader as tokio::io::async_read::asyncread>::poll_read_generated",
    description: "Generated profile for <tokio_util::io::stream_reader::StreamReader as tokio::io::async_read::AsyncRead>::poll_read from CodeQL/Pysa",
    detect_imports: TOKIO_UTIL_IO_STREAM_READER_STREAMREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_IMPORTS,
    sources: TOKIO_UTIL_IO_STREAM_READER_STREAMREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SOURCES,
    sinks: TOKIO_UTIL_IO_STREAM_READER_STREAMREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SINKS,
    sanitizers: TOKIO_UTIL_IO_STREAM_READER_STREAMREADER_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
