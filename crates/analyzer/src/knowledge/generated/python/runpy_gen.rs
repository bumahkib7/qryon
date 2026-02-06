//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static RUNPY_GEN_SOURCES: &[SourceDef] = &[];

static RUNPY_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "runpy.run_module",
        pattern: SinkKind::FunctionCall("runpy.run_module"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: runpy.run_module (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "runpy.run_path",
        pattern: SinkKind::FunctionCall("runpy.run_path"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: runpy.run_path (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
];

static RUNPY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static RUNPY_GEN_IMPORTS: &[&str] = &["runpy"];

pub static RUNPY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "runpy_generated",
    description: "Generated profile for runpy from CodeQL/Pysa",
    detect_imports: RUNPY_GEN_IMPORTS,
    sources: RUNPY_GEN_SOURCES,
    sinks: RUNPY_GEN_SINKS,
    sanitizers: RUNPY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
