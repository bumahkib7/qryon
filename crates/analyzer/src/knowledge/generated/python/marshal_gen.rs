//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MARSHAL_GEN_SOURCES: &[SourceDef] = &[];

static MARSHAL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "marshal.loads",
        pattern: SinkKind::FunctionCall("marshal.loads"),
        rule_id: "python/gen-pysa-execdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: marshal.loads (kind: ExecDeserializationSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "marshal.load",
        pattern: SinkKind::FunctionCall("marshal.load"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: marshal.load (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "marshal.dump",
        pattern: SinkKind::FunctionCall("marshal.dump"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: marshal.dump (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
];

static MARSHAL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MARSHAL_GEN_IMPORTS: &[&str] = &["marshal"];

pub static MARSHAL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "marshal_generated",
    description: "Generated profile for marshal from CodeQL/Pysa",
    detect_imports: MARSHAL_GEN_IMPORTS,
    sources: MARSHAL_GEN_SOURCES,
    sinks: MARSHAL_GEN_SINKS,
    sanitizers: MARSHAL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
