//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static JSONPICKLE_GEN_SOURCES: &[SourceDef] = &[];

static JSONPICKLE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "jsonpickle.decode",
        pattern: SinkKind::FunctionCall("jsonpickle.decode"),
        rule_id: "python/gen-pysa-execdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: jsonpickle.decode (kind: ExecDeserializationSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "jsonpickle.loads",
        pattern: SinkKind::FunctionCall("jsonpickle.loads"),
        rule_id: "python/gen-pysa-execdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: jsonpickle.loads (kind: ExecDeserializationSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "jsonpickle.unpickler.decode",
        pattern: SinkKind::FunctionCall("jsonpickle.unpickler.decode"),
        rule_id: "python/gen-pysa-execdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: jsonpickle.unpickler.decode (kind: ExecDeserializationSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "jsonpickle.unpickler.loadclass",
        pattern: SinkKind::FunctionCall("jsonpickle.unpickler.loadclass"),
        rule_id: "python/gen-pysa-getattr",
        severity: Severity::Error,
        description: "Pysa sink: jsonpickle.unpickler.loadclass (kind: GetAttr)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "jsonpickle.unpickler.loadrepr",
        pattern: SinkKind::FunctionCall("jsonpickle.unpickler.loadrepr"),
        rule_id: "python/gen-pysa-execdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: jsonpickle.unpickler.loadrepr (kind: ExecDeserializationSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "jsonpickle.util.is_installed",
        pattern: SinkKind::FunctionCall("jsonpickle.util.is_installed"),
        rule_id: "python/gen-pysa-execdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: jsonpickle.util.is_installed (kind: ExecDeserializationSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "jsonpickle.backend.JSONBackend.load_backend",
        pattern: SinkKind::FunctionCall("jsonpickle.backend.JSONBackend.load_backend"),
        rule_id: "python/gen-pysa-execdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: jsonpickle.backend.JSONBackend.load_backend (kind: ExecDeserializationSink)",
        cwe: Some("CWE-74"),
    },
];

static JSONPICKLE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static JSONPICKLE_GEN_IMPORTS: &[&str] = &["jsonpickle"];

pub static JSONPICKLE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "jsonpickle_generated",
    description: "Generated profile for jsonpickle from CodeQL/Pysa",
    detect_imports: JSONPICKLE_GEN_IMPORTS,
    sources: JSONPICKLE_GEN_SOURCES,
    sinks: JSONPICKLE_GEN_SINKS,
    sanitizers: JSONPICKLE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
