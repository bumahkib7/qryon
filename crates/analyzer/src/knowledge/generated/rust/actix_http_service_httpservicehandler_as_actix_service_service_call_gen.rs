//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_HTTP_SERVICE_HTTPSERVICEHANDLER_AS_ACTIX_SERVICE_SERVICE_CALL_GEN_SOURCES:
    &[SourceDef] = &[];

static ACTIX_HTTP_SERVICE_HTTPSERVICEHANDLER_AS_ACTIX_SERVICE_SERVICE_CALL_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<actix_http::service::HttpServiceHandler as actix_service::Service>::call.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    }];

static ACTIX_HTTP_SERVICE_HTTPSERVICEHANDLER_AS_ACTIX_SERVICE_SERVICE_CALL_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static ACTIX_HTTP_SERVICE_HTTPSERVICEHANDLER_AS_ACTIX_SERVICE_SERVICE_CALL_GEN_IMPORTS: &[&str] =
    &["<actix_http::service::HttpServiceHandler as actix_service::Service>::call"];

pub static ACTIX_HTTP_SERVICE_HTTPSERVICEHANDLER_AS_ACTIX_SERVICE_SERVICE_CALL_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<actix_http::service::httpservicehandler as actix_service::service>::call_generated",
    description: "Generated profile for <actix_http::service::HttpServiceHandler as actix_service::Service>::call from CodeQL/Pysa",
    detect_imports: ACTIX_HTTP_SERVICE_HTTPSERVICEHANDLER_AS_ACTIX_SERVICE_SERVICE_CALL_GEN_IMPORTS,
    sources: ACTIX_HTTP_SERVICE_HTTPSERVICEHANDLER_AS_ACTIX_SERVICE_SERVICE_CALL_GEN_SOURCES,
    sinks: ACTIX_HTTP_SERVICE_HTTPSERVICEHANDLER_AS_ACTIX_SERVICE_SERVICE_CALL_GEN_SINKS,
    sanitizers: ACTIX_HTTP_SERVICE_HTTPSERVICEHANDLER_AS_ACTIX_SERVICE_SERVICE_CALL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
