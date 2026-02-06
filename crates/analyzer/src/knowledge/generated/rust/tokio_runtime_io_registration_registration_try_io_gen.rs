//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_RUNTIME_IO_REGISTRATION_REGISTRATION_TRY_IO_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_RUNTIME_IO_REGISTRATION_REGISTRATION_TRY_IO_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::runtime::io::registration::Registration>::try_io.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[1] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_RUNTIME_IO_REGISTRATION_REGISTRATION_TRY_IO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_RUNTIME_IO_REGISTRATION_REGISTRATION_TRY_IO_GEN_IMPORTS: &[&str] =
    &["<tokio::runtime::io::registration::Registration>::try_io"];

pub static TOKIO_RUNTIME_IO_REGISTRATION_REGISTRATION_TRY_IO_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::runtime::io::registration::registration>::try_io_generated",
        description: "Generated profile for <tokio::runtime::io::registration::Registration>::try_io from CodeQL/Pysa",
        detect_imports: TOKIO_RUNTIME_IO_REGISTRATION_REGISTRATION_TRY_IO_GEN_IMPORTS,
        sources: TOKIO_RUNTIME_IO_REGISTRATION_REGISTRATION_TRY_IO_GEN_SOURCES,
        sinks: TOKIO_RUNTIME_IO_REGISTRATION_REGISTRATION_TRY_IO_GEN_SINKS,
        sanitizers: TOKIO_RUNTIME_IO_REGISTRATION_REGISTRATION_TRY_IO_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
