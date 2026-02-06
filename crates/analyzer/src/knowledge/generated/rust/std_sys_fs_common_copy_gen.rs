//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_FS_COMMON_COPY_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "std::sys::fs::common::copy.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static STD_SYS_FS_COMMON_COPY_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "std::sys::fs::common::copy.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-path-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Argument[0] (kind: path-injection)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "std::sys::fs::common::copy.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-path-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Argument[1] (kind: path-injection)",
        cwe: Some("CWE-22"),
    },
];

static STD_SYS_FS_COMMON_COPY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_FS_COMMON_COPY_GEN_IMPORTS: &[&str] = &["std::sys::fs::common::copy"];

pub static STD_SYS_FS_COMMON_COPY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::sys::fs::common::copy_generated",
    description: "Generated profile for std::sys::fs::common::copy from CodeQL/Pysa",
    detect_imports: STD_SYS_FS_COMMON_COPY_GEN_IMPORTS,
    sources: STD_SYS_FS_COMMON_COPY_GEN_SOURCES,
    sinks: STD_SYS_FS_COMMON_COPY_GEN_SINKS,
    sanitizers: STD_SYS_FS_COMMON_COPY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
