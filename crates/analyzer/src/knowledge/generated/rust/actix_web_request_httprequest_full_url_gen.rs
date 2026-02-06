//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_REQUEST_HTTPREQUEST_FULL_URL_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_WEB_REQUEST_HTTPREQUEST_FULL_URL_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_web::request::HttpRequest>::full_url.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ACTIX_WEB_REQUEST_HTTPREQUEST_FULL_URL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_WEB_REQUEST_HTTPREQUEST_FULL_URL_GEN_IMPORTS: &[&str] =
    &["<actix_web::request::HttpRequest>::full_url"];

pub static ACTIX_WEB_REQUEST_HTTPREQUEST_FULL_URL_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<actix_web::request::httprequest>::full_url_generated",
        description: "Generated profile for <actix_web::request::HttpRequest>::full_url from CodeQL/Pysa",
        detect_imports: ACTIX_WEB_REQUEST_HTTPREQUEST_FULL_URL_GEN_IMPORTS,
        sources: ACTIX_WEB_REQUEST_HTTPREQUEST_FULL_URL_GEN_SOURCES,
        sinks: ACTIX_WEB_REQUEST_HTTPREQUEST_FULL_URL_GEN_SINKS,
        sanitizers: ACTIX_WEB_REQUEST_HTTPREQUEST_FULL_URL_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
