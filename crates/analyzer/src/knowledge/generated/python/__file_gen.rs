//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static __FILE_GEN_SOURCES: &[SourceDef] = &[];

static __FILE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "__file",
    pattern: SinkKind::FunctionCall("__file"),
    rule_id: "python/gen-pysa-execdeserializationsink",
    severity: Severity::Error,
    description: "Pysa sink: __file (kind: ExecDeserializationSink)",
    cwe: Some("CWE-74"),
}];

static __FILE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static __FILE_GEN_IMPORTS: &[&str] = &["__file"];

pub static __FILE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "__file_generated",
    description: "Generated profile for __file from CodeQL/Pysa",
    detect_imports: __FILE_GEN_IMPORTS,
    sources: __FILE_GEN_SOURCES,
    sinks: __FILE_GEN_SINKS,
    sanitizers: __FILE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
