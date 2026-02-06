//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_IO_UTIL_BUF_STREAM_BUFSTREAM_WITH_CAPACITY_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_IO_UTIL_BUF_STREAM_BUFSTREAM_WITH_CAPACITY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::io::util::buf_stream::BufStream>::with_capacity.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[1] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static TOKIO_IO_UTIL_BUF_STREAM_BUFSTREAM_WITH_CAPACITY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_IO_UTIL_BUF_STREAM_BUFSTREAM_WITH_CAPACITY_GEN_IMPORTS: &[&str] =
    &["<tokio::io::util::buf_stream::BufStream>::with_capacity"];

pub static TOKIO_IO_UTIL_BUF_STREAM_BUFSTREAM_WITH_CAPACITY_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::io::util::buf_stream::bufstream>::with_capacity_generated",
        description: "Generated profile for <tokio::io::util::buf_stream::BufStream>::with_capacity from CodeQL/Pysa",
        detect_imports: TOKIO_IO_UTIL_BUF_STREAM_BUFSTREAM_WITH_CAPACITY_GEN_IMPORTS,
        sources: TOKIO_IO_UTIL_BUF_STREAM_BUFSTREAM_WITH_CAPACITY_GEN_SOURCES,
        sinks: TOKIO_IO_UTIL_BUF_STREAM_BUFSTREAM_WITH_CAPACITY_GEN_SINKS,
        sanitizers: TOKIO_IO_UTIL_BUF_STREAM_BUFSTREAM_WITH_CAPACITY_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
