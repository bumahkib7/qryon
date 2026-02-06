//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static DILL_GEN_SOURCES: &[SourceDef] = &[];

static DILL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "dill._dill.load",
        pattern: SinkKind::FunctionCall("dill._dill.load"),
        rule_id: "python/gen-pysa-execdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: dill._dill.load (kind: ExecDeserializationSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "dill._dill.loads",
        pattern: SinkKind::FunctionCall("dill._dill.loads"),
        rule_id: "python/gen-pysa-execdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: dill._dill.loads (kind: ExecDeserializationSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "dill._dill.load_session",
        pattern: SinkKind::FunctionCall("dill._dill.load_session"),
        rule_id: "python/gen-pysa-execdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: dill._dill.load_session (kind: ExecDeserializationSink)",
        cwe: Some("CWE-74"),
    },
];

static DILL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static DILL_GEN_IMPORTS: &[&str] = &["dill"];

pub static DILL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "dill_generated",
    description: "Generated profile for dill from CodeQL/Pysa",
    detect_imports: DILL_GEN_IMPORTS,
    sources: DILL_GEN_SOURCES,
    sinks: DILL_GEN_SINKS,
    sanitizers: DILL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
