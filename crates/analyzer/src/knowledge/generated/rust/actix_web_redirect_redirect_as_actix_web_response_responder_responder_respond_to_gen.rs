//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_REDIRECT_REDIRECT_AS_ACTIX_WEB_RESPONSE_RESPONDER_RESPONDER_RESPOND_TO_GEN_SOURCES: &[SourceDef] = &[
];

static ACTIX_WEB_REDIRECT_REDIRECT_AS_ACTIX_WEB_RESPONSE_RESPONDER_RESPONDER_RESPOND_TO_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<actix_web::redirect::Redirect as actix_web::response::responder::Responder>::respond_to.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static ACTIX_WEB_REDIRECT_REDIRECT_AS_ACTIX_WEB_RESPONSE_RESPONDER_RESPONDER_RESPOND_TO_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static ACTIX_WEB_REDIRECT_REDIRECT_AS_ACTIX_WEB_RESPONSE_RESPONDER_RESPONDER_RESPOND_TO_GEN_IMPORTS: &[&str] = &[
    "<actix_web::redirect::Redirect as actix_web::response::responder::Responder>::respond_to",
];

pub static ACTIX_WEB_REDIRECT_REDIRECT_AS_ACTIX_WEB_RESPONSE_RESPONDER_RESPONDER_RESPOND_TO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<actix_web::redirect::redirect as actix_web::response::responder::responder>::respond_to_generated",
    description: "Generated profile for <actix_web::redirect::Redirect as actix_web::response::responder::Responder>::respond_to from CodeQL/Pysa",
    detect_imports: ACTIX_WEB_REDIRECT_REDIRECT_AS_ACTIX_WEB_RESPONSE_RESPONDER_RESPONDER_RESPOND_TO_GEN_IMPORTS,
    sources: ACTIX_WEB_REDIRECT_REDIRECT_AS_ACTIX_WEB_RESPONSE_RESPONDER_RESPONDER_RESPOND_TO_GEN_SOURCES,
    sinks: ACTIX_WEB_REDIRECT_REDIRECT_AS_ACTIX_WEB_RESPONSE_RESPONDER_RESPONDER_RESPOND_TO_GEN_SINKS,
    sanitizers: ACTIX_WEB_REDIRECT_REDIRECT_AS_ACTIX_WEB_RESPONSE_RESPONDER_RESPONDER_RESPOND_TO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
