//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LINECACHE_GEN_SOURCES: &[SourceDef] = &[];

static LINECACHE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "linecache.getline",
        pattern: SinkKind::FunctionCall("linecache.getline"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: linecache.getline (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "linecache.lazycache",
        pattern: SinkKind::FunctionCall("linecache.lazycache"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: linecache.lazycache (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
];

static LINECACHE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LINECACHE_GEN_IMPORTS: &[&str] = &["linecache"];

pub static LINECACHE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "linecache_generated",
    description: "Generated profile for linecache from CodeQL/Pysa",
    detect_imports: LINECACHE_GEN_IMPORTS,
    sources: LINECACHE_GEN_SOURCES,
    sinks: LINECACHE_GEN_SINKS,
    sanitizers: LINECACHE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
