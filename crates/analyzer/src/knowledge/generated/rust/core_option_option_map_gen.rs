//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_OPTION_OPTION_MAP_GEN_SOURCES: &[SourceDef] = &[];

static CORE_OPTION_OPTION_MAP_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<core::option::Option>::map.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
    SinkDef {
        name: "<core::option::Option>::map.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static CORE_OPTION_OPTION_MAP_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_OPTION_OPTION_MAP_GEN_IMPORTS: &[&str] = &["<core::option::Option>::map"];

pub static CORE_OPTION_OPTION_MAP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<core::option::option>::map_generated",
    description: "Generated profile for <core::option::Option>::map from CodeQL/Pysa",
    detect_imports: CORE_OPTION_OPTION_MAP_GEN_IMPORTS,
    sources: CORE_OPTION_OPTION_MAP_GEN_SOURCES,
    sinks: CORE_OPTION_OPTION_MAP_GEN_SINKS,
    sanitizers: CORE_OPTION_OPTION_MAP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
