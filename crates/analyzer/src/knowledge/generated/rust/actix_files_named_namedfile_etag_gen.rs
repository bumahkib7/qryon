//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_FILES_NAMED_NAMEDFILE_ETAG_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_FILES_NAMED_NAMEDFILE_ETAG_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_files::named::NamedFile>::etag.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static ACTIX_FILES_NAMED_NAMEDFILE_ETAG_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_FILES_NAMED_NAMEDFILE_ETAG_GEN_IMPORTS: &[&str] =
    &["<actix_files::named::NamedFile>::etag"];

pub static ACTIX_FILES_NAMED_NAMEDFILE_ETAG_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<actix_files::named::namedfile>::etag_generated",
    description: "Generated profile for <actix_files::named::NamedFile>::etag from CodeQL/Pysa",
    detect_imports: ACTIX_FILES_NAMED_NAMEDFILE_ETAG_GEN_IMPORTS,
    sources: ACTIX_FILES_NAMED_NAMEDFILE_ETAG_GEN_SOURCES,
    sinks: ACTIX_FILES_NAMED_NAMEDFILE_ETAG_GEN_SINKS,
    sanitizers: ACTIX_FILES_NAMED_NAMEDFILE_ETAG_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
