//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LOG_RECORDBUILDER_MODULE_PATH_STATIC_GEN_SOURCES: &[SourceDef] = &[];

static LOG_RECORDBUILDER_MODULE_PATH_STATIC_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<log::RecordBuilder>::module_path_static.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static LOG_RECORDBUILDER_MODULE_PATH_STATIC_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LOG_RECORDBUILDER_MODULE_PATH_STATIC_GEN_IMPORTS: &[&str] =
    &["<log::RecordBuilder>::module_path_static"];

pub static LOG_RECORDBUILDER_MODULE_PATH_STATIC_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<log::recordbuilder>::module_path_static_generated",
    description: "Generated profile for <log::RecordBuilder>::module_path_static from CodeQL/Pysa",
    detect_imports: LOG_RECORDBUILDER_MODULE_PATH_STATIC_GEN_IMPORTS,
    sources: LOG_RECORDBUILDER_MODULE_PATH_STATIC_GEN_SOURCES,
    sinks: LOG_RECORDBUILDER_MODULE_PATH_STATIC_GEN_SINKS,
    sanitizers: LOG_RECORDBUILDER_MODULE_PATH_STATIC_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
