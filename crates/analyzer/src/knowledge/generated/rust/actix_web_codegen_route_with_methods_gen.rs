//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_CODEGEN_ROUTE_WITH_METHODS_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_WEB_CODEGEN_ROUTE_WITH_METHODS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "actix_web_codegen::route::with_methods.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static ACTIX_WEB_CODEGEN_ROUTE_WITH_METHODS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_WEB_CODEGEN_ROUTE_WITH_METHODS_GEN_IMPORTS: &[&str] =
    &["actix_web_codegen::route::with_methods"];

pub static ACTIX_WEB_CODEGEN_ROUTE_WITH_METHODS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "actix_web_codegen::route::with_methods_generated",
    description: "Generated profile for actix_web_codegen::route::with_methods from CodeQL/Pysa",
    detect_imports: ACTIX_WEB_CODEGEN_ROUTE_WITH_METHODS_GEN_IMPORTS,
    sources: ACTIX_WEB_CODEGEN_ROUTE_WITH_METHODS_GEN_SOURCES,
    sinks: ACTIX_WEB_CODEGEN_ROUTE_WITH_METHODS_GEN_SINKS,
    sanitizers: ACTIX_WEB_CODEGEN_ROUTE_WITH_METHODS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
