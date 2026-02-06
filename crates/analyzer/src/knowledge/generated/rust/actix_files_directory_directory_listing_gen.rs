//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_FILES_DIRECTORY_DIRECTORY_LISTING_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "actix_files::directory::directory_listing.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static ACTIX_FILES_DIRECTORY_DIRECTORY_LISTING_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "actix_files::directory::directory_listing.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-path-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Argument[0] (kind: path-injection)",
    cwe: Some("CWE-22"),
}];

static ACTIX_FILES_DIRECTORY_DIRECTORY_LISTING_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_FILES_DIRECTORY_DIRECTORY_LISTING_GEN_IMPORTS: &[&str] =
    &["actix_files::directory::directory_listing"];

pub static ACTIX_FILES_DIRECTORY_DIRECTORY_LISTING_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "actix_files::directory::directory_listing_generated",
        description: "Generated profile for actix_files::directory::directory_listing from CodeQL/Pysa",
        detect_imports: ACTIX_FILES_DIRECTORY_DIRECTORY_LISTING_GEN_IMPORTS,
        sources: ACTIX_FILES_DIRECTORY_DIRECTORY_LISTING_GEN_SOURCES,
        sinks: ACTIX_FILES_DIRECTORY_DIRECTORY_LISTING_GEN_SINKS,
        sanitizers: ACTIX_FILES_DIRECTORY_DIRECTORY_LISTING_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
