//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_HTTP_HEADER_RANGE_RANGE_BYTES_MULTI_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_WEB_HTTP_HEADER_RANGE_RANGE_BYTES_MULTI_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_web::http::header::range::Range>::bytes_multi.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static ACTIX_WEB_HTTP_HEADER_RANGE_RANGE_BYTES_MULTI_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_WEB_HTTP_HEADER_RANGE_RANGE_BYTES_MULTI_GEN_IMPORTS: &[&str] =
    &["<actix_web::http::header::range::Range>::bytes_multi"];

pub static ACTIX_WEB_HTTP_HEADER_RANGE_RANGE_BYTES_MULTI_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<actix_web::http::header::range::range>::bytes_multi_generated",
        description: "Generated profile for <actix_web::http::header::range::Range>::bytes_multi from CodeQL/Pysa",
        detect_imports: ACTIX_WEB_HTTP_HEADER_RANGE_RANGE_BYTES_MULTI_GEN_IMPORTS,
        sources: ACTIX_WEB_HTTP_HEADER_RANGE_RANGE_BYTES_MULTI_GEN_SOURCES,
        sinks: ACTIX_WEB_HTTP_HEADER_RANGE_RANGE_BYTES_MULTI_GEN_SINKS,
        sanitizers: ACTIX_WEB_HTTP_HEADER_RANGE_RANGE_BYTES_MULTI_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
