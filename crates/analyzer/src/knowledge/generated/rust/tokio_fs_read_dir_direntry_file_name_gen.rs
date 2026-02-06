//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_FS_READ_DIR_DIRENTRY_FILE_NAME_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<tokio::fs::read_dir::DirEntry>::file_name.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static TOKIO_FS_READ_DIR_DIRENTRY_FILE_NAME_GEN_SINKS: &[SinkDef] = &[];

static TOKIO_FS_READ_DIR_DIRENTRY_FILE_NAME_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_FS_READ_DIR_DIRENTRY_FILE_NAME_GEN_IMPORTS: &[&str] =
    &["<tokio::fs::read_dir::DirEntry>::file_name"];

pub static TOKIO_FS_READ_DIR_DIRENTRY_FILE_NAME_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<tokio::fs::read_dir::direntry>::file_name_generated",
    description: "Generated profile for <tokio::fs::read_dir::DirEntry>::file_name from CodeQL/Pysa",
    detect_imports: TOKIO_FS_READ_DIR_DIRENTRY_FILE_NAME_GEN_IMPORTS,
    sources: TOKIO_FS_READ_DIR_DIRENTRY_FILE_NAME_GEN_SOURCES,
    sinks: TOKIO_FS_READ_DIR_DIRENTRY_FILE_NAME_GEN_SINKS,
    sanitizers: TOKIO_FS_READ_DIR_DIRENTRY_FILE_NAME_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
