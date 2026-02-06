//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_FILES_NAMED_NAMEDFILE_INTO_RESPONSE_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_FILES_NAMED_NAMEDFILE_INTO_RESPONSE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_files::named::NamedFile>::into_response.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ACTIX_FILES_NAMED_NAMEDFILE_INTO_RESPONSE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_FILES_NAMED_NAMEDFILE_INTO_RESPONSE_GEN_IMPORTS: &[&str] =
    &["<actix_files::named::NamedFile>::into_response"];

pub static ACTIX_FILES_NAMED_NAMEDFILE_INTO_RESPONSE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<actix_files::named::namedfile>::into_response_generated",
        description: "Generated profile for <actix_files::named::NamedFile>::into_response from CodeQL/Pysa",
        detect_imports: ACTIX_FILES_NAMED_NAMEDFILE_INTO_RESPONSE_GEN_IMPORTS,
        sources: ACTIX_FILES_NAMED_NAMEDFILE_INTO_RESPONSE_GEN_SOURCES,
        sinks: ACTIX_FILES_NAMED_NAMEDFILE_INTO_RESPONSE_GEN_SINKS,
        sanitizers: ACTIX_FILES_NAMED_NAMEDFILE_INTO_RESPONSE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
