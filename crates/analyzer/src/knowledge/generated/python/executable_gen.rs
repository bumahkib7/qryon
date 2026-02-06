//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static EXECUTABLE_GEN_SOURCES: &[SourceDef] = &[];

static EXECUTABLE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "executable",
    pattern: SinkKind::FunctionCall("executable"),
    rule_id: "python/gen-pysa-execargsink",
    severity: Severity::Error,
    description: "Pysa sink: executable (kind: ExecArgSink)",
    cwe: Some("CWE-74"),
}];

static EXECUTABLE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static EXECUTABLE_GEN_IMPORTS: &[&str] = &["executable"];

pub static EXECUTABLE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "executable_generated",
    description: "Generated profile for executable from CodeQL/Pysa",
    detect_imports: EXECUTABLE_GEN_IMPORTS,
    sources: EXECUTABLE_GEN_SOURCES,
    sinks: EXECUTABLE_GEN_SINKS,
    sanitizers: EXECUTABLE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
