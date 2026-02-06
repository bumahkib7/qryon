//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PIL_GEN_SOURCES: &[SourceDef] = &[];

static PIL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "PIL.Image.open",
        pattern: SinkKind::FunctionCall("PIL.Image.open"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: PIL.Image.open (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "PIL.Image.Image.save",
        pattern: SinkKind::FunctionCall("PIL.Image.Image.save"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: PIL.Image.Image.save (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
];

static PIL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PIL_GEN_IMPORTS: &[&str] = &["PIL"];

pub static PIL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "pil_generated",
    description: "Generated profile for PIL from CodeQL/Pysa",
    detect_imports: PIL_GEN_IMPORTS,
    sources: PIL_GEN_SOURCES,
    sinks: PIL_GEN_SINKS,
    sanitizers: PIL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
