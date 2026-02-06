//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_FILES_FILES_FILES_NEW_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_FILES_FILES_FILES_NEW_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_files::files::Files>::new.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[1] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static ACTIX_FILES_FILES_FILES_NEW_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_FILES_FILES_FILES_NEW_GEN_IMPORTS: &[&str] = &["<actix_files::files::Files>::new"];

pub static ACTIX_FILES_FILES_FILES_NEW_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<actix_files::files::files>::new_generated",
    description: "Generated profile for <actix_files::files::Files>::new from CodeQL/Pysa",
    detect_imports: ACTIX_FILES_FILES_FILES_NEW_GEN_IMPORTS,
    sources: ACTIX_FILES_FILES_FILES_NEW_GEN_SOURCES,
    sinks: ACTIX_FILES_FILES_FILES_NEW_GEN_SINKS,
    sanitizers: ACTIX_FILES_FILES_FILES_NEW_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
