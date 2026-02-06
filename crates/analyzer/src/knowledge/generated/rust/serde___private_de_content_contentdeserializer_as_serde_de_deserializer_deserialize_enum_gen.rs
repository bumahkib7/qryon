//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SERDE___PRIVATE_DE_CONTENT_CONTENTDESERIALIZER_AS_SERDE_DE_DESERIALIZER_DESERIALIZE_ENUM_GEN_SOURCES: &[SourceDef] = &[
];

static SERDE___PRIVATE_DE_CONTENT_CONTENTDESERIALIZER_AS_SERDE_DE_DESERIALIZER_DESERIALIZE_ENUM_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<serde::__private::de::content::ContentDeserializer as serde::de::Deserializer>::deserialize_enum.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
];

static SERDE___PRIVATE_DE_CONTENT_CONTENTDESERIALIZER_AS_SERDE_DE_DESERIALIZER_DESERIALIZE_ENUM_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static SERDE___PRIVATE_DE_CONTENT_CONTENTDESERIALIZER_AS_SERDE_DE_DESERIALIZER_DESERIALIZE_ENUM_GEN_IMPORTS: &[&str] = &[
    "<serde::__private::de::content::ContentDeserializer as serde::de::Deserializer>::deserialize_enum",
];

pub static SERDE___PRIVATE_DE_CONTENT_CONTENTDESERIALIZER_AS_SERDE_DE_DESERIALIZER_DESERIALIZE_ENUM_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<serde::__private::de::content::contentdeserializer as serde::de::deserializer>::deserialize_enum_generated",
    description: "Generated profile for <serde::__private::de::content::ContentDeserializer as serde::de::Deserializer>::deserialize_enum from CodeQL/Pysa",
    detect_imports: SERDE___PRIVATE_DE_CONTENT_CONTENTDESERIALIZER_AS_SERDE_DE_DESERIALIZER_DESERIALIZE_ENUM_GEN_IMPORTS,
    sources: SERDE___PRIVATE_DE_CONTENT_CONTENTDESERIALIZER_AS_SERDE_DE_DESERIALIZER_DESERIALIZE_ENUM_GEN_SOURCES,
    sinks: SERDE___PRIVATE_DE_CONTENT_CONTENTDESERIALIZER_AS_SERDE_DE_DESERIALIZER_DESERIALIZE_ENUM_GEN_SINKS,
    sanitizers: SERDE___PRIVATE_DE_CONTENT_CONTENTDESERIALIZER_AS_SERDE_DE_DESERIALIZER_DESERIALIZE_ENUM_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
