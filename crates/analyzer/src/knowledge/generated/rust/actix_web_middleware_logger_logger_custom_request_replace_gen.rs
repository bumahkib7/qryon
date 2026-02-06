//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_MIDDLEWARE_LOGGER_LOGGER_CUSTOM_REQUEST_REPLACE_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_WEB_MIDDLEWARE_LOGGER_LOGGER_CUSTOM_REQUEST_REPLACE_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<actix_web::middleware::logger::Logger>::custom_request_replace.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static ACTIX_WEB_MIDDLEWARE_LOGGER_LOGGER_CUSTOM_REQUEST_REPLACE_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static ACTIX_WEB_MIDDLEWARE_LOGGER_LOGGER_CUSTOM_REQUEST_REPLACE_GEN_IMPORTS: &[&str] =
    &["<actix_web::middleware::logger::Logger>::custom_request_replace"];

pub static ACTIX_WEB_MIDDLEWARE_LOGGER_LOGGER_CUSTOM_REQUEST_REPLACE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<actix_web::middleware::logger::logger>::custom_request_replace_generated",
        description: "Generated profile for <actix_web::middleware::logger::Logger>::custom_request_replace from CodeQL/Pysa",
        detect_imports: ACTIX_WEB_MIDDLEWARE_LOGGER_LOGGER_CUSTOM_REQUEST_REPLACE_GEN_IMPORTS,
        sources: ACTIX_WEB_MIDDLEWARE_LOGGER_LOGGER_CUSTOM_REQUEST_REPLACE_GEN_SOURCES,
        sinks: ACTIX_WEB_MIDDLEWARE_LOGGER_LOGGER_CUSTOM_REQUEST_REPLACE_GEN_SINKS,
        sanitizers: ACTIX_WEB_MIDDLEWARE_LOGGER_LOGGER_CUSTOM_REQUEST_REPLACE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
