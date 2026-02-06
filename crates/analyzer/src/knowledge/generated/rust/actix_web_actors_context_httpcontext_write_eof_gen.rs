//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_WEB_ACTORS_CONTEXT_HTTPCONTEXT_WRITE_EOF_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_WEB_ACTORS_CONTEXT_HTTPCONTEXT_WRITE_EOF_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_web_actors::context::HttpContext>::write_eof.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static ACTIX_WEB_ACTORS_CONTEXT_HTTPCONTEXT_WRITE_EOF_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_WEB_ACTORS_CONTEXT_HTTPCONTEXT_WRITE_EOF_GEN_IMPORTS: &[&str] =
    &["<actix_web_actors::context::HttpContext>::write_eof"];

pub static ACTIX_WEB_ACTORS_CONTEXT_HTTPCONTEXT_WRITE_EOF_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<actix_web_actors::context::httpcontext>::write_eof_generated",
        description: "Generated profile for <actix_web_actors::context::HttpContext>::write_eof from CodeQL/Pysa",
        detect_imports: ACTIX_WEB_ACTORS_CONTEXT_HTTPCONTEXT_WRITE_EOF_GEN_IMPORTS,
        sources: ACTIX_WEB_ACTORS_CONTEXT_HTTPCONTEXT_WRITE_EOF_GEN_SOURCES,
        sinks: ACTIX_WEB_ACTORS_CONTEXT_HTTPCONTEXT_WRITE_EOF_GEN_SINKS,
        sanitizers: ACTIX_WEB_ACTORS_CONTEXT_HTTPCONTEXT_WRITE_EOF_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
