//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static NAME_GEN_SOURCES: &[SourceDef] = &[];

static NAME_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "name",
    pattern: SinkKind::FunctionCall("name"),
    rule_id: "python/gen-pysa-execimportsink",
    severity: Severity::Error,
    description: "Pysa sink: name (kind: ExecImportSink)",
    cwe: Some("CWE-74"),
}];

static NAME_GEN_SANITIZERS: &[SanitizerDef] = &[];

static NAME_GEN_IMPORTS: &[&str] = &["name"];

pub static NAME_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "name_generated",
    description: "Generated profile for name from CodeQL/Pysa",
    detect_imports: NAME_GEN_IMPORTS,
    sources: NAME_GEN_SOURCES,
    sinks: NAME_GEN_SINKS,
    sanitizers: NAME_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
