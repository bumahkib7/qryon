//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static EVAL_GEN_SOURCES: &[SourceDef] = &[];

static EVAL_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "eval",
    pattern: SinkKind::FunctionCall("eval"),
    rule_id: "python/gen-pysa-remotecodeexecution",
    severity: Severity::Critical,
    description: "Pysa sink: eval (kind: RemoteCodeExecution)",
    cwe: Some("CWE-78"),
}];

static EVAL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static EVAL_GEN_IMPORTS: &[&str] = &["eval"];

pub static EVAL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "eval_generated",
    description: "Generated profile for eval from CodeQL/Pysa",
    detect_imports: EVAL_GEN_IMPORTS,
    sources: EVAL_GEN_SOURCES,
    sinks: EVAL_GEN_SINKS,
    sanitizers: EVAL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
