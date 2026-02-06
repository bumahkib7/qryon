//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_IO_READ_BUF_READBUF_PUT_SLICE_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_IO_READ_BUF_READBUF_PUT_SLICE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::io::read_buf::ReadBuf>::put_slice.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_IO_READ_BUF_READBUF_PUT_SLICE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_IO_READ_BUF_READBUF_PUT_SLICE_GEN_IMPORTS: &[&str] =
    &["<tokio::io::read_buf::ReadBuf>::put_slice"];

pub static TOKIO_IO_READ_BUF_READBUF_PUT_SLICE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<tokio::io::read_buf::readbuf>::put_slice_generated",
    description: "Generated profile for <tokio::io::read_buf::ReadBuf>::put_slice from CodeQL/Pysa",
    detect_imports: TOKIO_IO_READ_BUF_READBUF_PUT_SLICE_GEN_IMPORTS,
    sources: TOKIO_IO_READ_BUF_READBUF_PUT_SLICE_GEN_SOURCES,
    sinks: TOKIO_IO_READ_BUF_READBUF_PUT_SLICE_GEN_SINKS,
    sanitizers: TOKIO_IO_READ_BUF_READBUF_PUT_SLICE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
