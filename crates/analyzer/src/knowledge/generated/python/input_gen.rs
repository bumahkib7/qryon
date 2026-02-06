//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static INPUT_GEN_SOURCES: &[SourceDef] = &[];

static INPUT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "input",
    pattern: SinkKind::FunctionCall("input"),
    rule_id: "python/gen-pysa-execargsink",
    severity: Severity::Error,
    description: "Pysa sink: input (kind: ExecArgSink)",
    cwe: Some("CWE-74"),
}];

static INPUT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static INPUT_GEN_IMPORTS: &[&str] = &["input"];

pub static INPUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "input_generated",
    description: "Generated profile for input from CodeQL/Pysa",
    detect_imports: INPUT_GEN_IMPORTS,
    sources: INPUT_GEN_SOURCES,
    sinks: INPUT_GEN_SINKS,
    sanitizers: INPUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
