//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STDIN_GEN_SOURCES: &[SourceDef] = &[];

static STDIN_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "stdin",
    pattern: SinkKind::FunctionCall("stdin"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: stdin (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static STDIN_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STDIN_GEN_IMPORTS: &[&str] = &["stdin"];

pub static STDIN_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "stdin_generated",
    description: "Generated profile for stdin from CodeQL/Pysa",
    detect_imports: STDIN_GEN_IMPORTS,
    sources: STDIN_GEN_SOURCES,
    sinks: STDIN_GEN_SINKS,
    sanitizers: STDIN_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
