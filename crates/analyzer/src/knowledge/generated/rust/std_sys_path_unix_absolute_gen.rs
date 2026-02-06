//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_PATH_UNIX_ABSOLUTE_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "std::sys::path::unix::absolute.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue (kind: commandargs)",
}];

static STD_SYS_PATH_UNIX_ABSOLUTE_GEN_SINKS: &[SinkDef] = &[];

static STD_SYS_PATH_UNIX_ABSOLUTE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_PATH_UNIX_ABSOLUTE_GEN_IMPORTS: &[&str] = &["std::sys::path::unix::absolute"];

pub static STD_SYS_PATH_UNIX_ABSOLUTE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::sys::path::unix::absolute_generated",
    description: "Generated profile for std::sys::path::unix::absolute from CodeQL/Pysa",
    detect_imports: STD_SYS_PATH_UNIX_ABSOLUTE_GEN_IMPORTS,
    sources: STD_SYS_PATH_UNIX_ABSOLUTE_GEN_SOURCES,
    sinks: STD_SYS_PATH_UNIX_ABSOLUTE_GEN_SINKS,
    sanitizers: STD_SYS_PATH_UNIX_ABSOLUTE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
