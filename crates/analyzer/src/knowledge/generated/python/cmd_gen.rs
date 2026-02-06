//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CMD_GEN_SOURCES: &[SourceDef] = &[];

static CMD_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "cmd",
    pattern: SinkKind::FunctionCall("cmd"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: cmd (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static CMD_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CMD_GEN_IMPORTS: &[&str] = &["cmd"];

pub static CMD_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "cmd_generated",
    description: "Generated profile for cmd from CodeQL/Pysa",
    detect_imports: CMD_GEN_IMPORTS,
    sources: CMD_GEN_SOURCES,
    sinks: CMD_GEN_SINKS,
    sanitizers: CMD_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
