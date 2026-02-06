//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_HTTP_HEADER_ENTITY_ENTITYTAG_WEAK_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_WEB_HTTP_HEADER_ENTITY_ENTITYTAG_WEAK_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_web::http::header::entity::EntityTag>::weak.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static ACTIX_WEB_HTTP_HEADER_ENTITY_ENTITYTAG_WEAK_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_WEB_HTTP_HEADER_ENTITY_ENTITYTAG_WEAK_GEN_IMPORTS: &[&str] =
    &["<actix_web::http::header::entity::EntityTag>::weak"];

pub static ACTIX_WEB_HTTP_HEADER_ENTITY_ENTITYTAG_WEAK_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<actix_web::http::header::entity::entitytag>::weak_generated",
        description: "Generated profile for <actix_web::http::header::entity::EntityTag>::weak from CodeQL/Pysa",
        detect_imports: ACTIX_WEB_HTTP_HEADER_ENTITY_ENTITYTAG_WEAK_GEN_IMPORTS,
        sources: ACTIX_WEB_HTTP_HEADER_ENTITY_ENTITYTAG_WEAK_GEN_SOURCES,
        sinks: ACTIX_WEB_HTTP_HEADER_ENTITY_ENTITYTAG_WEAK_GEN_SINKS,
        sanitizers: ACTIX_WEB_HTTP_HEADER_ENTITY_ENTITYTAG_WEAK_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
