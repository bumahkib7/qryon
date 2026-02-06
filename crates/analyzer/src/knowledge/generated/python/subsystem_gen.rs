//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SUBSYSTEM_GEN_SOURCES: &[SourceDef] = &[];

static SUBSYSTEM_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "subsystem",
    pattern: SinkKind::FunctionCall("subsystem"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: subsystem (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static SUBSYSTEM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SUBSYSTEM_GEN_IMPORTS: &[&str] = &["subsystem"];

pub static SUBSYSTEM_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "subsystem_generated",
    description: "Generated profile for subsystem from CodeQL/Pysa",
    detect_imports: SUBSYSTEM_GEN_IMPORTS,
    sources: SUBSYSTEM_GEN_SOURCES,
    sinks: SUBSYSTEM_GEN_SINKS,
    sanitizers: SUBSYSTEM_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
