//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PREEXEC_FN_GEN_SOURCES: &[SourceDef] = &[];

static PREEXEC_FN_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "preexec_fn",
    pattern: SinkKind::FunctionCall("preexec_fn"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: preexec_fn (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static PREEXEC_FN_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PREEXEC_FN_GEN_IMPORTS: &[&str] = &["preexec_fn"];

pub static PREEXEC_FN_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "preexec_fn_generated",
    description: "Generated profile for preexec_fn from CodeQL/Pysa",
    detect_imports: PREEXEC_FN_GEN_IMPORTS,
    sources: PREEXEC_FN_GEN_SOURCES,
    sinks: PREEXEC_FN_GEN_SINKS,
    sanitizers: PREEXEC_FN_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
