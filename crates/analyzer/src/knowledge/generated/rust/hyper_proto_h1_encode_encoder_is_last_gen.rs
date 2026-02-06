//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_PROTO_H1_ENCODE_ENCODER_IS_LAST_GEN_SOURCES: &[SourceDef] = &[];

static HYPER_PROTO_H1_ENCODE_ENCODER_IS_LAST_GEN_SINKS: &[SinkDef] = &[];

static HYPER_PROTO_H1_ENCODE_ENCODER_IS_LAST_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "<hyper::proto::h1::encode::Encoder>::is_last.Argument[self].Reference.Field[hyper::proto::h1::encode::Encoder::is_last]",
    pattern: SanitizerKind::Function(
        "Argument[self].Reference.Field[hyper::proto::h1::encode::Encoder::is_last]",
    ),
    sanitizes: "general",
    description: "CodeQL sanitizer: Argument[self].Reference.Field[hyper::proto::h1::encode::Encoder::is_last]",
}];

static HYPER_PROTO_H1_ENCODE_ENCODER_IS_LAST_GEN_IMPORTS: &[&str] =
    &["<hyper::proto::h1::encode::Encoder>::is_last"];

pub static HYPER_PROTO_H1_ENCODE_ENCODER_IS_LAST_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<hyper::proto::h1::encode::encoder>::is_last_generated",
    description: "Generated profile for <hyper::proto::h1::encode::Encoder>::is_last from CodeQL/Pysa",
    detect_imports: HYPER_PROTO_H1_ENCODE_ENCODER_IS_LAST_GEN_IMPORTS,
    sources: HYPER_PROTO_H1_ENCODE_ENCODER_IS_LAST_GEN_SOURCES,
    sinks: HYPER_PROTO_H1_ENCODE_ENCODER_IS_LAST_GEN_SINKS,
    sanitizers: HYPER_PROTO_H1_ENCODE_ENCODER_IS_LAST_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
