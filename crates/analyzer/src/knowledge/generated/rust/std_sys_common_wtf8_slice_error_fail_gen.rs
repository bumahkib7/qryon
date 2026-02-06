//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_COMMON_WTF8_SLICE_ERROR_FAIL_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYS_COMMON_WTF8_SLICE_ERROR_FAIL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "std::sys_common::wtf8::slice_error_fail.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
    SinkDef {
        name: "std::sys_common::wtf8::slice_error_fail.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[1] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
    SinkDef {
        name: "std::sys_common::wtf8::slice_error_fail.Argument[2]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[2] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static STD_SYS_COMMON_WTF8_SLICE_ERROR_FAIL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_COMMON_WTF8_SLICE_ERROR_FAIL_GEN_IMPORTS: &[&str] =
    &["std::sys_common::wtf8::slice_error_fail"];

pub static STD_SYS_COMMON_WTF8_SLICE_ERROR_FAIL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "std::sys_common::wtf8::slice_error_fail_generated",
    description: "Generated profile for std::sys_common::wtf8::slice_error_fail from CodeQL/Pysa",
    detect_imports: STD_SYS_COMMON_WTF8_SLICE_ERROR_FAIL_GEN_IMPORTS,
    sources: STD_SYS_COMMON_WTF8_SLICE_ERROR_FAIL_GEN_SOURCES,
    sinks: STD_SYS_COMMON_WTF8_SLICE_ERROR_FAIL_GEN_SINKS,
    sanitizers: STD_SYS_COMMON_WTF8_SLICE_ERROR_FAIL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
