//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_PROTO_H1_ENCODE_ENCODER_ENCODE_AND_END_GEN_SOURCES: &[SourceDef] = &[];

static HYPER_PROTO_H1_ENCODE_ENCODER_ENCODE_AND_END_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<hyper::proto::h1::encode::Encoder>::encode_and_end.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[1] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static HYPER_PROTO_H1_ENCODE_ENCODER_ENCODE_AND_END_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HYPER_PROTO_H1_ENCODE_ENCODER_ENCODE_AND_END_GEN_IMPORTS: &[&str] =
    &["<hyper::proto::h1::encode::Encoder>::encode_and_end"];

pub static HYPER_PROTO_H1_ENCODE_ENCODER_ENCODE_AND_END_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<hyper::proto::h1::encode::encoder>::encode_and_end_generated",
        description: "Generated profile for <hyper::proto::h1::encode::Encoder>::encode_and_end from CodeQL/Pysa",
        detect_imports: HYPER_PROTO_H1_ENCODE_ENCODER_ENCODE_AND_END_GEN_IMPORTS,
        sources: HYPER_PROTO_H1_ENCODE_ENCODER_ENCODE_AND_END_GEN_SOURCES,
        sinks: HYPER_PROTO_H1_ENCODE_ENCODER_ENCODE_AND_END_GEN_SINKS,
        sanitizers: HYPER_PROTO_H1_ENCODE_ENCODER_ENCODE_AND_END_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
