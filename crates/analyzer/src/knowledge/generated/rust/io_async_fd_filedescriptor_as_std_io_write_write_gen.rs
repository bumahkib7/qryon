//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static IO_ASYNC_FD_FILEDESCRIPTOR_AS_STD_IO_WRITE_WRITE_GEN_SOURCES: &[SourceDef] = &[];

static IO_ASYNC_FD_FILEDESCRIPTOR_AS_STD_IO_WRITE_WRITE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<io_async_fd::FileDescriptor as std::io::Write>::write.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static IO_ASYNC_FD_FILEDESCRIPTOR_AS_STD_IO_WRITE_WRITE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static IO_ASYNC_FD_FILEDESCRIPTOR_AS_STD_IO_WRITE_WRITE_GEN_IMPORTS: &[&str] =
    &["<io_async_fd::FileDescriptor as std::io::Write>::write"];

pub static IO_ASYNC_FD_FILEDESCRIPTOR_AS_STD_IO_WRITE_WRITE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<io_async_fd::filedescriptor as std::io::write>::write_generated",
        description: "Generated profile for <io_async_fd::FileDescriptor as std::io::Write>::write from CodeQL/Pysa",
        detect_imports: IO_ASYNC_FD_FILEDESCRIPTOR_AS_STD_IO_WRITE_WRITE_GEN_IMPORTS,
        sources: IO_ASYNC_FD_FILEDESCRIPTOR_AS_STD_IO_WRITE_WRITE_GEN_SOURCES,
        sinks: IO_ASYNC_FD_FILEDESCRIPTOR_AS_STD_IO_WRITE_WRITE_GEN_SINKS,
        sanitizers: IO_ASYNC_FD_FILEDESCRIPTOR_AS_STD_IO_WRITE_WRITE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
