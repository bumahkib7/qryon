//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SERDE___PRIVATE_SER_TAGGEDSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_MAP_GEN_SOURCES:
    &[SourceDef] = &[];

static SERDE___PRIVATE_SER_TAGGEDSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_MAP_GEN_SINKS:
    &[SinkDef] = &[SinkDef {
    name: "<serde::__private::ser::TaggedSerializer as serde::ser::Serializer>::serialize_map.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static SERDE___PRIVATE_SER_TAGGEDSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_MAP_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static SERDE___PRIVATE_SER_TAGGEDSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_MAP_GEN_IMPORTS:
    &[&str] =
    &["<serde::__private::ser::TaggedSerializer as serde::ser::Serializer>::serialize_map"];

pub static SERDE___PRIVATE_SER_TAGGEDSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_MAP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<serde::__private::ser::taggedserializer as serde::ser::serializer>::serialize_map_generated",
    description: "Generated profile for <serde::__private::ser::TaggedSerializer as serde::ser::Serializer>::serialize_map from CodeQL/Pysa",
    detect_imports: SERDE___PRIVATE_SER_TAGGEDSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_MAP_GEN_IMPORTS,
    sources: SERDE___PRIVATE_SER_TAGGEDSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_MAP_GEN_SOURCES,
    sinks: SERDE___PRIVATE_SER_TAGGEDSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_MAP_GEN_SINKS,
    sanitizers: SERDE___PRIVATE_SER_TAGGEDSERIALIZER_AS_SERDE_SER_SERIALIZER_SERIALIZE_MAP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
