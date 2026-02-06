//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_PAL_UNIX_OS_TEMP_DIR_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "std::sys::pal::unix::os::temp_dir.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "env_input",
    description: "CodeQL source: ReturnValue (kind: environment)",
}];

static STD_SYS_PAL_UNIX_OS_TEMP_DIR_GEN_SINKS: &[SinkDef] = &[];

static STD_SYS_PAL_UNIX_OS_TEMP_DIR_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_PAL_UNIX_OS_TEMP_DIR_GEN_IMPORTS: &[&str] = &["std::sys::pal::unix::os::temp_dir"];

pub static STD_SYS_PAL_UNIX_OS_TEMP_DIR_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::sys::pal::unix::os::temp_dir_generated",
    description: "Generated profile for std::sys::pal::unix::os::temp_dir from CodeQL/Pysa",
    detect_imports: STD_SYS_PAL_UNIX_OS_TEMP_DIR_GEN_IMPORTS,
    sources: STD_SYS_PAL_UNIX_OS_TEMP_DIR_GEN_SOURCES,
    sinks: STD_SYS_PAL_UNIX_OS_TEMP_DIR_GEN_SINKS,
    sanitizers: STD_SYS_PAL_UNIX_OS_TEMP_DIR_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
