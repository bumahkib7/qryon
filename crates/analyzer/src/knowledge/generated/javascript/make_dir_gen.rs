//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MAKE_DIR_GEN_SOURCES: &[SourceDef] = &[];

static MAKE_DIR_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "make-dir.Member[makeDirectory,makeDirectorySync].Argument[0]",
    pattern: SinkKind::FunctionCall("makeDirectory,makeDirectorySync"),
    rule_id: "javascript/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Member[makeDirectory,makeDirectorySync].Argument[0] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static MAKE_DIR_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MAKE_DIR_GEN_IMPORTS: &[&str] = &["make-dir"];

pub static MAKE_DIR_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "make_dir_generated",
    description: "Generated profile for make-dir from CodeQL/Pysa",
    detect_imports: MAKE_DIR_GEN_IMPORTS,
    sources: MAKE_DIR_GEN_SOURCES,
    sinks: MAKE_DIR_GEN_SINKS,
    sanitizers: MAKE_DIR_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
