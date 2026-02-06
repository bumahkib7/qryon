//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_SCOPE_SCOPE_AS_ACTIX_WEB_SERVICE_HTTPSERVICEFACTORY_REGISTER_GEN_SOURCES:
    &[SourceDef] = &[];

static ACTIX_WEB_SCOPE_SCOPE_AS_ACTIX_WEB_SERVICE_HTTPSERVICEFACTORY_REGISTER_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<actix_web::scope::Scope as actix_web::service::HttpServiceFactory>::register.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ACTIX_WEB_SCOPE_SCOPE_AS_ACTIX_WEB_SERVICE_HTTPSERVICEFACTORY_REGISTER_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static ACTIX_WEB_SCOPE_SCOPE_AS_ACTIX_WEB_SERVICE_HTTPSERVICEFACTORY_REGISTER_GEN_IMPORTS:
    &[&str] = &["<actix_web::scope::Scope as actix_web::service::HttpServiceFactory>::register"];

pub static ACTIX_WEB_SCOPE_SCOPE_AS_ACTIX_WEB_SERVICE_HTTPSERVICEFACTORY_REGISTER_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<actix_web::scope::scope as actix_web::service::httpservicefactory>::register_generated",
    description: "Generated profile for <actix_web::scope::Scope as actix_web::service::HttpServiceFactory>::register from CodeQL/Pysa",
    detect_imports:
        ACTIX_WEB_SCOPE_SCOPE_AS_ACTIX_WEB_SERVICE_HTTPSERVICEFACTORY_REGISTER_GEN_IMPORTS,
    sources: ACTIX_WEB_SCOPE_SCOPE_AS_ACTIX_WEB_SERVICE_HTTPSERVICEFACTORY_REGISTER_GEN_SOURCES,
    sinks: ACTIX_WEB_SCOPE_SCOPE_AS_ACTIX_WEB_SERVICE_HTTPSERVICEFACTORY_REGISTER_GEN_SINKS,
    sanitizers:
        ACTIX_WEB_SCOPE_SCOPE_AS_ACTIX_WEB_SERVICE_HTTPSERVICEFACTORY_REGISTER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
