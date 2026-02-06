//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_FS_READ_TO_STRING_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "std::fs::read_to_string.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static STD_FS_READ_TO_STRING_GEN_SINKS: &[SinkDef] = &[];

static STD_FS_READ_TO_STRING_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_FS_READ_TO_STRING_GEN_IMPORTS: &[&str] = &["std::fs::read_to_string"];

pub static STD_FS_READ_TO_STRING_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::fs::read_to_string_generated",
    description: "Generated profile for std::fs::read_to_string from CodeQL/Pysa",
    detect_imports: STD_FS_READ_TO_STRING_GEN_IMPORTS,
    sources: STD_FS_READ_TO_STRING_GEN_SOURCES,
    sinks: STD_FS_READ_TO_STRING_GEN_SINKS,
    sanitizers: STD_FS_READ_TO_STRING_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
