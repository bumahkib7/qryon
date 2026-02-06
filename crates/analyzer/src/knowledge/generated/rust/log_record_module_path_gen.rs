//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LOG_RECORD_MODULE_PATH_GEN_SOURCES: &[SourceDef] = &[];

static LOG_RECORD_MODULE_PATH_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<log::Record>::module_path.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static LOG_RECORD_MODULE_PATH_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LOG_RECORD_MODULE_PATH_GEN_IMPORTS: &[&str] = &["<log::Record>::module_path"];

pub static LOG_RECORD_MODULE_PATH_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<log::record>::module_path_generated",
    description: "Generated profile for <log::Record>::module_path from CodeQL/Pysa",
    detect_imports: LOG_RECORD_MODULE_PATH_GEN_IMPORTS,
    sources: LOG_RECORD_MODULE_PATH_GEN_SOURCES,
    sinks: LOG_RECORD_MODULE_PATH_GEN_SINKS,
    sanitizers: LOG_RECORD_MODULE_PATH_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
