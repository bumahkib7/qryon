//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LENGTH_DELIMITED_MOCK_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SOURCES:
    &[SourceDef] = &[];

static LENGTH_DELIMITED_MOCK_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<length_delimited::Mock as tokio::io::async_read::AsyncRead>::poll_read.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[1] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static LENGTH_DELIMITED_MOCK_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static LENGTH_DELIMITED_MOCK_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_IMPORTS: &[&str] =
    &["<length_delimited::Mock as tokio::io::async_read::AsyncRead>::poll_read"];

pub static LENGTH_DELIMITED_MOCK_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<length_delimited::mock as tokio::io::async_read::asyncread>::poll_read_generated",
    description: "Generated profile for <length_delimited::Mock as tokio::io::async_read::AsyncRead>::poll_read from CodeQL/Pysa",
    detect_imports: LENGTH_DELIMITED_MOCK_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_IMPORTS,
    sources: LENGTH_DELIMITED_MOCK_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SOURCES,
    sinks: LENGTH_DELIMITED_MOCK_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SINKS,
    sanitizers: LENGTH_DELIMITED_MOCK_AS_TOKIO_IO_ASYNC_READ_ASYNCREAD_POLL_READ_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
