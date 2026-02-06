//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_FS_COMMON_EXISTS_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYS_FS_COMMON_EXISTS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "std::sys::fs::common::exists.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[0] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static STD_SYS_FS_COMMON_EXISTS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_FS_COMMON_EXISTS_GEN_IMPORTS: &[&str] = &["std::sys::fs::common::exists"];

pub static STD_SYS_FS_COMMON_EXISTS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::sys::fs::common::exists_generated",
    description: "Generated profile for std::sys::fs::common::exists from CodeQL/Pysa",
    detect_imports: STD_SYS_FS_COMMON_EXISTS_GEN_IMPORTS,
    sources: STD_SYS_FS_COMMON_EXISTS_GEN_SOURCES,
    sinks: STD_SYS_FS_COMMON_EXISTS_GEN_SINKS,
    sanitizers: STD_SYS_FS_COMMON_EXISTS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
