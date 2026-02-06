//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_FS_FILE_OPEN_BUFFERED_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<std::fs::File>::open_buffered.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static STD_FS_FILE_OPEN_BUFFERED_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::fs::File>::open_buffered.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[0] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static STD_FS_FILE_OPEN_BUFFERED_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_FS_FILE_OPEN_BUFFERED_GEN_IMPORTS: &[&str] = &["<std::fs::File>::open_buffered"];

pub static STD_FS_FILE_OPEN_BUFFERED_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<std::fs::file>::open_buffered_generated",
    description: "Generated profile for <std::fs::File>::open_buffered from CodeQL/Pysa",
    detect_imports: STD_FS_FILE_OPEN_BUFFERED_GEN_IMPORTS,
    sources: STD_FS_FILE_OPEN_BUFFERED_GEN_SOURCES,
    sinks: STD_FS_FILE_OPEN_BUFFERED_GEN_SINKS,
    sanitizers: STD_FS_FILE_OPEN_BUFFERED_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
