//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLOSE_FDS_GEN_SOURCES: &[SourceDef] = &[];

static CLOSE_FDS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "close_fds",
    pattern: SinkKind::FunctionCall("close_fds"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: close_fds (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static CLOSE_FDS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CLOSE_FDS_GEN_IMPORTS: &[&str] = &["close_fds"];

pub static CLOSE_FDS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "close_fds_generated",
    description: "Generated profile for close_fds from CodeQL/Pysa",
    detect_imports: CLOSE_FDS_GEN_IMPORTS,
    sources: CLOSE_FDS_GEN_SOURCES,
    sinks: CLOSE_FDS_GEN_SINKS,
    sanitizers: CLOSE_FDS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
