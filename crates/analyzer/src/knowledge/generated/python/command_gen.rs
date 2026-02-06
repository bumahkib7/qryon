//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static COMMAND_GEN_SOURCES: &[SourceDef] = &[];

static COMMAND_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "command",
    pattern: SinkKind::FunctionCall("command"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: command (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static COMMAND_GEN_SANITIZERS: &[SanitizerDef] = &[];

static COMMAND_GEN_IMPORTS: &[&str] = &["command"];

pub static COMMAND_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "command_generated",
    description: "Generated profile for command from CodeQL/Pysa",
    detect_imports: COMMAND_GEN_IMPORTS,
    sources: COMMAND_GEN_SOURCES,
    sinks: COMMAND_GEN_SINKS,
    sanitizers: COMMAND_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
