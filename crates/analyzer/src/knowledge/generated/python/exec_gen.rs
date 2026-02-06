//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static EXEC_GEN_SOURCES: &[SourceDef] = &[];

static EXEC_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "exec",
    pattern: SinkKind::FunctionCall("exec"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: exec (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static EXEC_GEN_SANITIZERS: &[SanitizerDef] = &[];

static EXEC_GEN_IMPORTS: &[&str] = &["exec"];

pub static EXEC_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "exec_generated",
    description: "Generated profile for exec from CodeQL/Pysa",
    detect_imports: EXEC_GEN_IMPORTS,
    sources: EXEC_GEN_SOURCES,
    sinks: EXEC_GEN_SINKS,
    sanitizers: EXEC_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
