//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_FS_FILE_FILE_CREATE_NEW_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_FS_FILE_FILE_CREATE_NEW_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::fs::file::File>::create_new.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[0] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static TOKIO_FS_FILE_FILE_CREATE_NEW_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_FS_FILE_FILE_CREATE_NEW_GEN_IMPORTS: &[&str] =
    &["<tokio::fs::file::File>::create_new"];

pub static TOKIO_FS_FILE_FILE_CREATE_NEW_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<tokio::fs::file::file>::create_new_generated",
    description: "Generated profile for <tokio::fs::file::File>::create_new from CodeQL/Pysa",
    detect_imports: TOKIO_FS_FILE_FILE_CREATE_NEW_GEN_IMPORTS,
    sources: TOKIO_FS_FILE_FILE_CREATE_NEW_GEN_SOURCES,
    sinks: TOKIO_FS_FILE_FILE_CREATE_NEW_GEN_SINKS,
    sanitizers: TOKIO_FS_FILE_FILE_CREATE_NEW_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
