//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_PATH_ABSOLUTE_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "std::path::absolute.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: commandargs)",
}];

static STD_PATH_ABSOLUTE_GEN_SINKS: &[SinkDef] = &[];

static STD_PATH_ABSOLUTE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_PATH_ABSOLUTE_GEN_IMPORTS: &[&str] = &["std::path::absolute"];

pub static STD_PATH_ABSOLUTE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::path::absolute_generated",
    description: "Generated profile for std::path::absolute from CodeQL/Pysa",
    detect_imports: STD_PATH_ABSOLUTE_GEN_IMPORTS,
    sources: STD_PATH_ABSOLUTE_GEN_SOURCES,
    sinks: STD_PATH_ABSOLUTE_GEN_SINKS,
    sanitizers: STD_PATH_ABSOLUTE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
