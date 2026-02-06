//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REQWEST_BLOCKING_MULTIPART_READER_AS_STD_IO_READ_READ_GEN_SOURCES: &[SourceDef] = &[];

static REQWEST_BLOCKING_MULTIPART_READER_AS_STD_IO_READ_READ_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<reqwest::blocking::multipart::Reader as std::io::Read>::read.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static REQWEST_BLOCKING_MULTIPART_READER_AS_STD_IO_READ_READ_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REQWEST_BLOCKING_MULTIPART_READER_AS_STD_IO_READ_READ_GEN_IMPORTS: &[&str] =
    &["<reqwest::blocking::multipart::Reader as std::io::Read>::read"];

pub static REQWEST_BLOCKING_MULTIPART_READER_AS_STD_IO_READ_READ_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<reqwest::blocking::multipart::reader as std::io::read>::read_generated",
        description: "Generated profile for <reqwest::blocking::multipart::Reader as std::io::Read>::read from CodeQL/Pysa",
        detect_imports: REQWEST_BLOCKING_MULTIPART_READER_AS_STD_IO_READ_READ_GEN_IMPORTS,
        sources: REQWEST_BLOCKING_MULTIPART_READER_AS_STD_IO_READ_READ_GEN_SOURCES,
        sinks: REQWEST_BLOCKING_MULTIPART_READER_AS_STD_IO_READ_READ_GEN_SINKS,
        sanitizers: REQWEST_BLOCKING_MULTIPART_READER_AS_STD_IO_READ_READ_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
