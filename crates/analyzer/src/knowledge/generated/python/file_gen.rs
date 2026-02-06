//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FILE_GEN_SOURCES: &[SourceDef] = &[];

static FILE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "file",
    pattern: SinkKind::FunctionCall("file"),
    rule_id: "python/gen-pysa-execdeserializationsink",
    severity: Severity::Error,
    description: "Pysa sink: file (kind: ExecDeserializationSink)",
    cwe: Some("CWE-74"),
}];

static FILE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FILE_GEN_IMPORTS: &[&str] = &["file"];

pub static FILE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "file_generated",
    description: "Generated profile for file from CodeQL/Pysa",
    detect_imports: FILE_GEN_IMPORTS,
    sources: FILE_GEN_SOURCES,
    sinks: FILE_GEN_SINKS,
    sanitizers: FILE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
