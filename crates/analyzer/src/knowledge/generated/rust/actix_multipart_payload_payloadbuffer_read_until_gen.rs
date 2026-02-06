//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READ_UNTIL_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READ_UNTIL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<actix_multipart::payload::PayloadBuffer>::read_until.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[0] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "<actix_multipart::payload::PayloadBuffer>::read_until.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
];

static ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READ_UNTIL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READ_UNTIL_GEN_IMPORTS: &[&str] =
    &["<actix_multipart::payload::PayloadBuffer>::read_until"];

pub static ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READ_UNTIL_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<actix_multipart::payload::payloadbuffer>::read_until_generated",
        description: "Generated profile for <actix_multipart::payload::PayloadBuffer>::read_until from CodeQL/Pysa",
        detect_imports: ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READ_UNTIL_GEN_IMPORTS,
        sources: ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READ_UNTIL_GEN_SOURCES,
        sinks: ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READ_UNTIL_GEN_SINKS,
        sanitizers: ACTIX_MULTIPART_PAYLOAD_PAYLOADBUFFER_READ_UNTIL_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
