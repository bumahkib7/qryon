//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_IO_ERROR_ERROR_AS_CORE_CONVERT_FROM_FROM_GEN_SOURCES: &[SourceDef] = &[];

static STD_IO_ERROR_ERROR_AS_CORE_CONVERT_FROM_FROM_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::io::error::Error as core::convert::From>::from.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static STD_IO_ERROR_ERROR_AS_CORE_CONVERT_FROM_FROM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_IO_ERROR_ERROR_AS_CORE_CONVERT_FROM_FROM_GEN_IMPORTS: &[&str] =
    &["<std::io::error::Error as core::convert::From>::from"];

pub static STD_IO_ERROR_ERROR_AS_CORE_CONVERT_FROM_FROM_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::io::error::error as core::convert::from>::from_generated",
        description: "Generated profile for <std::io::error::Error as core::convert::From>::from from CodeQL/Pysa",
        detect_imports: STD_IO_ERROR_ERROR_AS_CORE_CONVERT_FROM_FROM_GEN_IMPORTS,
        sources: STD_IO_ERROR_ERROR_AS_CORE_CONVERT_FROM_FROM_GEN_SOURCES,
        sinks: STD_IO_ERROR_ERROR_AS_CORE_CONVERT_FROM_FROM_GEN_SINKS,
        sanitizers: STD_IO_ERROR_ERROR_AS_CORE_CONVERT_FROM_FROM_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
