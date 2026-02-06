//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static EXC_INFO_GEN_SOURCES: &[SourceDef] = &[];

static EXC_INFO_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "exc_info",
    pattern: SinkKind::FunctionCall("exc_info"),
    rule_id: "python/gen-pysa-logging",
    severity: Severity::Error,
    description: "Pysa sink: exc_info (kind: Logging)",
    cwe: Some("CWE-74"),
}];

static EXC_INFO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static EXC_INFO_GEN_IMPORTS: &[&str] = &["exc_info"];

pub static EXC_INFO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "exc_info_generated",
    description: "Generated profile for exc_info from CodeQL/Pysa",
    detect_imports: EXC_INFO_GEN_IMPORTS,
    sources: EXC_INFO_GEN_SOURCES,
    sinks: EXC_INFO_GEN_SINKS,
    sanitizers: EXC_INFO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
