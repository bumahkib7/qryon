//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HYPER_PROTO_H1_ENCODE_KIND_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES: &[SourceDef] = &[];

static HYPER_PROTO_H1_ENCODE_KIND_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS: &[SinkDef] = &[];

static HYPER_PROTO_H1_ENCODE_KIND_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "<hyper::proto::h1::encode::Kind as core::clone::Clone>::clone.Argument[self].Field[hyper::proto::h1::encode::Kind::Chunked(0)]",
        pattern: SanitizerKind::Function(
            "Argument[self].Field[hyper::proto::h1::encode::Kind::Chunked(0)]",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Field[hyper::proto::h1::encode::Kind::Chunked(0)]",
    },
    SanitizerDef {
        name: "<hyper::proto::h1::encode::Kind as core::clone::Clone>::clone.Argument[self].Field[hyper::proto::h1::encode::Kind::Length(0)]",
        pattern: SanitizerKind::Function(
            "Argument[self].Field[hyper::proto::h1::encode::Kind::Length(0)]",
        ),
        sanitizes: "general",
        description: "CodeQL sanitizer: Argument[self].Field[hyper::proto::h1::encode::Kind::Length(0)]",
    },
];

static HYPER_PROTO_H1_ENCODE_KIND_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS: &[&str] =
    &["<hyper::proto::h1::encode::Kind as core::clone::Clone>::clone"];

pub static HYPER_PROTO_H1_ENCODE_KIND_AS_CORE_CLONE_CLONE_CLONE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<hyper::proto::h1::encode::kind as core::clone::clone>::clone_generated",
        description: "Generated profile for <hyper::proto::h1::encode::Kind as core::clone::Clone>::clone from CodeQL/Pysa",
        detect_imports: HYPER_PROTO_H1_ENCODE_KIND_AS_CORE_CLONE_CLONE_CLONE_GEN_IMPORTS,
        sources: HYPER_PROTO_H1_ENCODE_KIND_AS_CORE_CLONE_CLONE_CLONE_GEN_SOURCES,
        sinks: HYPER_PROTO_H1_ENCODE_KIND_AS_CORE_CLONE_CLONE_CLONE_GEN_SINKS,
        sanitizers: HYPER_PROTO_H1_ENCODE_KIND_AS_CORE_CLONE_CLONE_CLONE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
