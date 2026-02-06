//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_HTTP_HEADER_ACCEPT_ENCODING_ACCEPTENCODING_RANKED_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_WEB_HTTP_HEADER_ACCEPT_ENCODING_ACCEPTENCODING_RANKED_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<actix_web::http::header::accept_encoding::AcceptEncoding>::ranked.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    }];

static ACTIX_WEB_HTTP_HEADER_ACCEPT_ENCODING_ACCEPTENCODING_RANKED_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static ACTIX_WEB_HTTP_HEADER_ACCEPT_ENCODING_ACCEPTENCODING_RANKED_GEN_IMPORTS: &[&str] =
    &["<actix_web::http::header::accept_encoding::AcceptEncoding>::ranked"];

pub static ACTIX_WEB_HTTP_HEADER_ACCEPT_ENCODING_ACCEPTENCODING_RANKED_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<actix_web::http::header::accept_encoding::acceptencoding>::ranked_generated",
    description: "Generated profile for <actix_web::http::header::accept_encoding::AcceptEncoding>::ranked from CodeQL/Pysa",
    detect_imports: ACTIX_WEB_HTTP_HEADER_ACCEPT_ENCODING_ACCEPTENCODING_RANKED_GEN_IMPORTS,
    sources: ACTIX_WEB_HTTP_HEADER_ACCEPT_ENCODING_ACCEPTENCODING_RANKED_GEN_SOURCES,
    sinks: ACTIX_WEB_HTTP_HEADER_ACCEPT_ENCODING_ACCEPTENCODING_RANKED_GEN_SINKS,
    sanitizers: ACTIX_WEB_HTTP_HEADER_ACCEPT_ENCODING_ACCEPTENCODING_RANKED_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
