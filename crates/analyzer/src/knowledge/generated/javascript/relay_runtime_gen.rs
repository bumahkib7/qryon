//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static RELAY_RUNTIME_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "relay-runtime.Member[readFragment].ReturnValue",
    pattern: SourceKind::MemberAccess("readFragment"),
    taint_label: "user_input",
    description: "CodeQL source: Member[readFragment].ReturnValue (kind: response)",
}];

static RELAY_RUNTIME_GEN_SINKS: &[SinkDef] = &[];

static RELAY_RUNTIME_GEN_SANITIZERS: &[SanitizerDef] = &[];

static RELAY_RUNTIME_GEN_IMPORTS: &[&str] = &["relay-runtime"];

pub static RELAY_RUNTIME_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "relay_runtime_generated",
    description: "Generated profile for relay-runtime from CodeQL/Pysa",
    detect_imports: RELAY_RUNTIME_GEN_IMPORTS,
    sources: RELAY_RUNTIME_GEN_SOURCES,
    sinks: RELAY_RUNTIME_GEN_SINKS,
    sanitizers: RELAY_RUNTIME_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
