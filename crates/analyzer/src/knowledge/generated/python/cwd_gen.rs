//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CWD_GEN_SOURCES: &[SourceDef] = &[];

static CWD_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "cwd",
    pattern: SinkKind::FunctionCall("cwd"),
    rule_id: "python/gen-pysa-execargsink",
    severity: Severity::Error,
    description: "Pysa sink: cwd (kind: ExecArgSink)",
    cwe: Some("CWE-74"),
}];

static CWD_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CWD_GEN_IMPORTS: &[&str] = &["cwd"];

pub static CWD_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "cwd_generated",
    description: "Generated profile for cwd from CodeQL/Pysa",
    detect_imports: CWD_GEN_IMPORTS,
    sources: CWD_GEN_SOURCES,
    sinks: CWD_GEN_SINKS,
    sanitizers: CWD_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
