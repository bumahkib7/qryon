//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ARGS_GEN_SOURCES: &[SourceDef] = &[];

static ARGS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "args",
    pattern: SinkKind::FunctionCall("args"),
    rule_id: "python/gen-pysa-execargsink",
    severity: Severity::Error,
    description: "Pysa sink: args (kind: ExecArgSink)",
    cwe: Some("CWE-74"),
}];

static ARGS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ARGS_GEN_IMPORTS: &[&str] = &["args"];

pub static ARGS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "args_generated",
    description: "Generated profile for args from CodeQL/Pysa",
    detect_imports: ARGS_GEN_IMPORTS,
    sources: ARGS_GEN_SOURCES,
    sinks: ARGS_GEN_SINKS,
    sanitizers: ARGS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
