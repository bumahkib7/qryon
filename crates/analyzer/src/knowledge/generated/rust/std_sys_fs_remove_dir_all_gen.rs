//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_FS_REMOVE_DIR_ALL_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "std::sys::fs::remove_dir_all.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static STD_SYS_FS_REMOVE_DIR_ALL_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "std::sys::fs::remove_dir_all.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[0] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static STD_SYS_FS_REMOVE_DIR_ALL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_FS_REMOVE_DIR_ALL_GEN_IMPORTS: &[&str] = &["std::sys::fs::remove_dir_all"];

pub static STD_SYS_FS_REMOVE_DIR_ALL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::sys::fs::remove_dir_all_generated",
    description: "Generated profile for std::sys::fs::remove_dir_all from CodeQL/Pysa",
    detect_imports: STD_SYS_FS_REMOVE_DIR_ALL_GEN_IMPORTS,
    sources: STD_SYS_FS_REMOVE_DIR_ALL_GEN_SOURCES,
    sinks: STD_SYS_FS_REMOVE_DIR_ALL_GEN_SINKS,
    sanitizers: STD_SYS_FS_REMOVE_DIR_ALL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
