//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_FS_COPY_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "std::fs::copy.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static STD_FS_COPY_GEN_SINKS: &[SinkDef] = &[];

static STD_FS_COPY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_FS_COPY_GEN_IMPORTS: &[&str] = &["std::fs::copy"];

pub static STD_FS_COPY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::fs::copy_generated",
    description: "Generated profile for std::fs::copy from CodeQL/Pysa",
    detect_imports: STD_FS_COPY_GEN_IMPORTS,
    sources: STD_FS_COPY_GEN_SOURCES,
    sinks: STD_FS_COPY_GEN_SINKS,
    sanitizers: STD_FS_COPY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
