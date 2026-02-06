//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_HTTP_H1_DISPATCHER_DISPATCHER_NEW_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_HTTP_H1_DISPATCHER_DISPATCHER_NEW_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_http::h1::dispatcher::Dispatcher>::new.Argument[4]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[4] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ACTIX_HTTP_H1_DISPATCHER_DISPATCHER_NEW_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_HTTP_H1_DISPATCHER_DISPATCHER_NEW_GEN_IMPORTS: &[&str] =
    &["<actix_http::h1::dispatcher::Dispatcher>::new"];

pub static ACTIX_HTTP_H1_DISPATCHER_DISPATCHER_NEW_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<actix_http::h1::dispatcher::dispatcher>::new_generated",
        description: "Generated profile for <actix_http::h1::dispatcher::Dispatcher>::new from CodeQL/Pysa",
        detect_imports: ACTIX_HTTP_H1_DISPATCHER_DISPATCHER_NEW_GEN_IMPORTS,
        sources: ACTIX_HTTP_H1_DISPATCHER_DISPATCHER_NEW_GEN_SOURCES,
        sinks: ACTIX_HTTP_H1_DISPATCHER_DISPATCHER_NEW_GEN_SINKS,
        sanitizers: ACTIX_HTTP_H1_DISPATCHER_DISPATCHER_NEW_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
