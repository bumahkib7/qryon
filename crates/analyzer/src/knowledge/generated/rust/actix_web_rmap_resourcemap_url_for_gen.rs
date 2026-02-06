//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_RMAP_RESOURCEMAP_URL_FOR_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_WEB_RMAP_RESOURCEMAP_URL_FOR_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_web::rmap::ResourceMap>::url_for.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ACTIX_WEB_RMAP_RESOURCEMAP_URL_FOR_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_WEB_RMAP_RESOURCEMAP_URL_FOR_GEN_IMPORTS: &[&str] =
    &["<actix_web::rmap::ResourceMap>::url_for"];

pub static ACTIX_WEB_RMAP_RESOURCEMAP_URL_FOR_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<actix_web::rmap::resourcemap>::url_for_generated",
    description: "Generated profile for <actix_web::rmap::ResourceMap>::url_for from CodeQL/Pysa",
    detect_imports: ACTIX_WEB_RMAP_RESOURCEMAP_URL_FOR_GEN_IMPORTS,
    sources: ACTIX_WEB_RMAP_RESOURCEMAP_URL_FOR_GEN_SOURCES,
    sinks: ACTIX_WEB_RMAP_RESOURCEMAP_URL_FOR_GEN_SINKS,
    sanitizers: ACTIX_WEB_RMAP_RESOURCEMAP_URL_FOR_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
