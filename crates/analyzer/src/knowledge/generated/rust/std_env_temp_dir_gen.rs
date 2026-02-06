//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_ENV_TEMP_DIR_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "std::env::temp_dir.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "env_input",
    description: "CodeQL source: ReturnValue (kind: environment)",
}];

static STD_ENV_TEMP_DIR_GEN_SINKS: &[SinkDef] = &[];

static STD_ENV_TEMP_DIR_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_ENV_TEMP_DIR_GEN_IMPORTS: &[&str] = &["std::env::temp_dir"];

pub static STD_ENV_TEMP_DIR_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::env::temp_dir_generated",
    description: "Generated profile for std::env::temp_dir from CodeQL/Pysa",
    detect_imports: STD_ENV_TEMP_DIR_GEN_IMPORTS,
    sources: STD_ENV_TEMP_DIR_GEN_SOURCES,
    sinks: STD_ENV_TEMP_DIR_GEN_SINKS,
    sanitizers: STD_ENV_TEMP_DIR_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
