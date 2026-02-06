//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static IMPORTLIB_GEN_SOURCES: &[SourceDef] = &[];

static IMPORTLIB_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "importlib.import_module",
    pattern: SinkKind::FunctionCall("importlib.import_module"),
    rule_id: "python/gen-pysa-execimportsink",
    severity: Severity::Error,
    description: "Pysa sink: importlib.import_module (kind: ExecImportSink)",
    cwe: Some("CWE-74"),
}];

static IMPORTLIB_GEN_SANITIZERS: &[SanitizerDef] = &[];

static IMPORTLIB_GEN_IMPORTS: &[&str] = &["importlib"];

pub static IMPORTLIB_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "importlib_generated",
    description: "Generated profile for importlib from CodeQL/Pysa",
    detect_imports: IMPORTLIB_GEN_IMPORTS,
    sources: IMPORTLIB_GEN_SOURCES,
    sinks: IMPORTLIB_GEN_SINKS,
    sanitizers: IMPORTLIB_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
