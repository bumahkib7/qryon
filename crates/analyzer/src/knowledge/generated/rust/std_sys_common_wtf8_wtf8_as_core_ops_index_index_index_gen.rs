//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_COMMON_WTF8_WTF8_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYS_COMMON_WTF8_WTF8_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<std::sys_common::wtf8::Wtf8 as core::ops::index::Index>::index.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
    SinkDef {
        name: "<std::sys_common::wtf8::Wtf8 as core::ops::index::Index>::index.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static STD_SYS_COMMON_WTF8_WTF8_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_COMMON_WTF8_WTF8_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_IMPORTS: &[&str] =
    &["<std::sys_common::wtf8::Wtf8 as core::ops::index::Index>::index"];

pub static STD_SYS_COMMON_WTF8_WTF8_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::sys_common::wtf8::wtf8 as core::ops::index::index>::index_generated",
        description: "Generated profile for <std::sys_common::wtf8::Wtf8 as core::ops::index::Index>::index from CodeQL/Pysa",
        detect_imports: STD_SYS_COMMON_WTF8_WTF8_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_IMPORTS,
        sources: STD_SYS_COMMON_WTF8_WTF8_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SOURCES,
        sinks: STD_SYS_COMMON_WTF8_WTF8_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SINKS,
        sanitizers: STD_SYS_COMMON_WTF8_WTF8_AS_CORE_OPS_INDEX_INDEX_INDEX_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
