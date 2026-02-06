//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_MULTIPART_FIELD_INNERFIELD_READ_STREAM_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_MULTIPART_FIELD_INNERFIELD_READ_STREAM_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_multipart::field::InnerField>::read_stream.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static ACTIX_MULTIPART_FIELD_INNERFIELD_READ_STREAM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_MULTIPART_FIELD_INNERFIELD_READ_STREAM_GEN_IMPORTS: &[&str] =
    &["<actix_multipart::field::InnerField>::read_stream"];

pub static ACTIX_MULTIPART_FIELD_INNERFIELD_READ_STREAM_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<actix_multipart::field::innerfield>::read_stream_generated",
        description: "Generated profile for <actix_multipart::field::InnerField>::read_stream from CodeQL/Pysa",
        detect_imports: ACTIX_MULTIPART_FIELD_INNERFIELD_READ_STREAM_GEN_IMPORTS,
        sources: ACTIX_MULTIPART_FIELD_INNERFIELD_READ_STREAM_GEN_SOURCES,
        sinks: ACTIX_MULTIPART_FIELD_INNERFIELD_READ_STREAM_GEN_SINKS,
        sanitizers: ACTIX_MULTIPART_FIELD_INNERFIELD_READ_STREAM_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
