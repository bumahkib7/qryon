//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_PATH_PATH_IS_SYMLINK_GEN_SOURCES: &[SourceDef] = &[];

static STD_PATH_PATH_IS_SYMLINK_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::path::Path>::is_symlink.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[self] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static STD_PATH_PATH_IS_SYMLINK_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_PATH_PATH_IS_SYMLINK_GEN_IMPORTS: &[&str] = &["<std::path::Path>::is_symlink"];

pub static STD_PATH_PATH_IS_SYMLINK_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<std::path::path>::is_symlink_generated",
    description: "Generated profile for <std::path::Path>::is_symlink from CodeQL/Pysa",
    detect_imports: STD_PATH_PATH_IS_SYMLINK_GEN_IMPORTS,
    sources: STD_PATH_PATH_IS_SYMLINK_GEN_SOURCES,
    sinks: STD_PATH_PATH_IS_SYMLINK_GEN_SINKS,
    sanitizers: STD_PATH_PATH_IS_SYMLINK_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
