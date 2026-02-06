//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_IO_STDIO_STDERR_AS_STD_IO_WRITE_WRITE_GEN_SOURCES: &[SourceDef] = &[];

static STD_IO_STDIO_STDERR_AS_STD_IO_WRITE_WRITE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::io::stdio::Stderr as std::io::Write>::write.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static STD_IO_STDIO_STDERR_AS_STD_IO_WRITE_WRITE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_IO_STDIO_STDERR_AS_STD_IO_WRITE_WRITE_GEN_IMPORTS: &[&str] =
    &["<std::io::stdio::Stderr as std::io::Write>::write"];

pub static STD_IO_STDIO_STDERR_AS_STD_IO_WRITE_WRITE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::io::stdio::stderr as std::io::write>::write_generated",
        description: "Generated profile for <std::io::stdio::Stderr as std::io::Write>::write from CodeQL/Pysa",
        detect_imports: STD_IO_STDIO_STDERR_AS_STD_IO_WRITE_WRITE_GEN_IMPORTS,
        sources: STD_IO_STDIO_STDERR_AS_STD_IO_WRITE_WRITE_GEN_SOURCES,
        sinks: STD_IO_STDIO_STDERR_AS_STD_IO_WRITE_WRITE_GEN_SINKS,
        sanitizers: STD_IO_STDIO_STDERR_AS_STD_IO_WRITE_WRITE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
