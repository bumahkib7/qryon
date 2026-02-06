//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PYRE_GEN_SOURCES: &[SourceDef] = &[];

static PYRE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "pyre._global_sink",
    pattern: SinkKind::FunctionCall("pyre._global_sink"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: pyre._global_sink (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static PYRE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PYRE_GEN_IMPORTS: &[&str] = &["pyre"];

pub static PYRE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "pyre_generated",
    description: "Generated profile for pyre from CodeQL/Pysa",
    detect_imports: PYRE_GEN_IMPORTS,
    sources: PYRE_GEN_SOURCES,
    sinks: PYRE_GEN_SINKS,
    sanitizers: PYRE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
