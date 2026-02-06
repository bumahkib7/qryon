//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AS_STD_IO_WRITE_WRITE_ALL_GEN_SOURCES: &[SourceDef] = &[];

static AS_STD_IO_WRITE_WRITE_ALL_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<& as std::io::Write>::write_all.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static AS_STD_IO_WRITE_WRITE_ALL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AS_STD_IO_WRITE_WRITE_ALL_GEN_IMPORTS: &[&str] = &["<& as std::io::Write>::write_all"];

pub static AS_STD_IO_WRITE_WRITE_ALL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<& as std::io::write>::write_all_generated",
    description: "Generated profile for <& as std::io::Write>::write_all from CodeQL/Pysa",
    detect_imports: AS_STD_IO_WRITE_WRITE_ALL_GEN_IMPORTS,
    sources: AS_STD_IO_WRITE_WRITE_ALL_GEN_SOURCES,
    sinks: AS_STD_IO_WRITE_WRITE_ALL_GEN_SINKS,
    sanitizers: AS_STD_IO_WRITE_WRITE_ALL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
