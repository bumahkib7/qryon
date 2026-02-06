//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_COMMON_WTF8_CHECK_UTF8_BOUNDARY_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYS_COMMON_WTF8_CHECK_UTF8_BOUNDARY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "std::sys_common::wtf8::check_utf8_boundary.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[1] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static STD_SYS_COMMON_WTF8_CHECK_UTF8_BOUNDARY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_COMMON_WTF8_CHECK_UTF8_BOUNDARY_GEN_IMPORTS: &[&str] =
    &["std::sys_common::wtf8::check_utf8_boundary"];

pub static STD_SYS_COMMON_WTF8_CHECK_UTF8_BOUNDARY_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "std::sys_common::wtf8::check_utf8_boundary_generated",
        description: "Generated profile for std::sys_common::wtf8::check_utf8_boundary from CodeQL/Pysa",
        detect_imports: STD_SYS_COMMON_WTF8_CHECK_UTF8_BOUNDARY_GEN_IMPORTS,
        sources: STD_SYS_COMMON_WTF8_CHECK_UTF8_BOUNDARY_GEN_SOURCES,
        sinks: STD_SYS_COMMON_WTF8_CHECK_UTF8_BOUNDARY_GEN_SINKS,
        sanitizers: STD_SYS_COMMON_WTF8_CHECK_UTF8_BOUNDARY_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
