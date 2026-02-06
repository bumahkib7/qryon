//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SERDE___PRIVATE_SER_CONTENT_CONTENTSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_TUPLE_VARIANT_GEN_SOURCES: &[SourceDef] = &[
];

static SERDE___PRIVATE_SER_CONTENT_CONTENTSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_TUPLE_VARIANT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<serde::__private::ser::content::ContentSerializer as serde::ser::Serializer>::serialize_tuple_variant.Argument[3]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[3] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static SERDE___PRIVATE_SER_CONTENT_CONTENTSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_TUPLE_VARIANT_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static SERDE___PRIVATE_SER_CONTENT_CONTENTSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_TUPLE_VARIANT_GEN_IMPORTS: &[&str] = &[
    "<serde::__private::ser::content::ContentSerializer as serde::ser::Serializer>::serialize_tuple_variant",
];

pub static SERDE___PRIVATE_SER_CONTENT_CONTENTSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_TUPLE_VARIANT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<serde::__private::ser::content::contentserializer as serde::ser::serializer>::serialize_tuple_variant_generated",
    description: "Generated profile for <serde::__private::ser::content::ContentSerializer as serde::ser::Serializer>::serialize_tuple_variant from CodeQL/Pysa",
    detect_imports: SERDE___PRIVATE_SER_CONTENT_CONTENTSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_TUPLE_VARIANT_GEN_IMPORTS,
    sources: SERDE___PRIVATE_SER_CONTENT_CONTENTSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_TUPLE_VARIANT_GEN_SOURCES,
    sinks: SERDE___PRIVATE_SER_CONTENT_CONTENTSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_TUPLE_VARIANT_GEN_SINKS,
    sanitizers: SERDE___PRIVATE_SER_CONTENT_CONTENTSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_TUPLE_VARIANT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
