//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SHELVE_GEN_SOURCES: &[SourceDef] = &[];

static SHELVE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "shelve.open",
        pattern: SinkKind::FunctionCall("shelve.open"),
        rule_id: "python/gen-pysa-filecontentdeserializationsink",
        severity: Severity::Error,
        description: "Pysa sink: shelve.open (kind: FileContentDeserializationSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "shelve.DbfilenameShelf.__init__",
        pattern: SinkKind::FunctionCall("shelve.DbfilenameShelf.__init__"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: shelve.DbfilenameShelf.__init__ (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
];

static SHELVE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SHELVE_GEN_IMPORTS: &[&str] = &["shelve"];

pub static SHELVE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "shelve_generated",
    description: "Generated profile for shelve from CodeQL/Pysa",
    detect_imports: SHELVE_GEN_IMPORTS,
    sources: SHELVE_GEN_SOURCES,
    sinks: SHELVE_GEN_SINKS,
    sanitizers: SHELVE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
