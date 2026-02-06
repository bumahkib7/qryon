//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READLINE_OR_EOF_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READLINE_OR_EOF_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_multipart::payload::PayloadBuffer>::readline_or_eof.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READLINE_OR_EOF_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READLINE_OR_EOF_GEN_IMPORTS: &[&str] =
    &["<actix_multipart::payload::PayloadBuffer>::readline_or_eof"];

pub static ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READLINE_OR_EOF_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<actix_multipart::payload::payloadbuffer>::readline_or_eof_generated",
        description: "Generated profile for <actix_multipart::payload::PayloadBuffer>::readline_or_eof from CodeQL/Pysa",
        detect_imports: ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READLINE_OR_EOF_GEN_IMPORTS,
        sources: ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READLINE_OR_EOF_GEN_SOURCES,
        sinks: ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READLINE_OR_EOF_GEN_SINKS,
        sanitizers: ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READLINE_OR_EOF_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
