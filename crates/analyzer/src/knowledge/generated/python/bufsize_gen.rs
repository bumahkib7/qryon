//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static BUFSIZE_GEN_SOURCES: &[SourceDef] = &[];

static BUFSIZE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "bufsize",
    pattern: SinkKind::FunctionCall("bufsize"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: bufsize (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static BUFSIZE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static BUFSIZE_GEN_IMPORTS: &[&str] = &["bufsize"];

pub static BUFSIZE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "bufsize_generated",
    description: "Generated profile for bufsize from CodeQL/Pysa",
    detect_imports: BUFSIZE_GEN_IMPORTS,
    sources: BUFSIZE_GEN_SOURCES,
    sinks: BUFSIZE_GEN_SINKS,
    sanitizers: BUFSIZE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
