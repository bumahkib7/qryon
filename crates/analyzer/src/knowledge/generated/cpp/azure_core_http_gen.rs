//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AZURE_CORE_HTTP_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "Azure::Core::Http.RawResponse.GetHeaders",
        pattern: SourceKind::MemberAccess("Azure::Core::Http.RawResponse.GetHeaders"),
        taint_label: "user_input",
        description: "CodeQL source: Azure::Core::Http.RawResponse.GetHeaders (kind: manual)",
    },
    SourceDef {
        name: "Azure::Core::Http.RawResponse.GetBody",
        pattern: SourceKind::MemberAccess("Azure::Core::Http.RawResponse.GetBody"),
        taint_label: "user_input",
        description: "CodeQL source: Azure::Core::Http.RawResponse.GetBody (kind: manual)",
    },
    SourceDef {
        name: "Azure::Core::Http.RawResponse.ExtractBodyStream",
        pattern: SourceKind::MemberAccess("Azure::Core::Http.RawResponse.ExtractBodyStream"),
        taint_label: "user_input",
        description: "CodeQL source: Azure::Core::Http.RawResponse.ExtractBodyStream (kind: manual)",
    },
    SourceDef {
        name: "Azure::Core::Http.Request.GetHeaders",
        pattern: SourceKind::MemberAccess("Azure::Core::Http.Request.GetHeaders"),
        taint_label: "user_input",
        description: "CodeQL source: Azure::Core::Http.Request.GetHeaders (kind: manual)",
    },
    SourceDef {
        name: "Azure::Core::Http.Request.GetHeader",
        pattern: SourceKind::MemberAccess("Azure::Core::Http.Request.GetHeader"),
        taint_label: "user_input",
        description: "CodeQL source: Azure::Core::Http.Request.GetHeader (kind: manual)",
    },
    SourceDef {
        name: "Azure::Core::Http.Request.GetBodyStream",
        pattern: SourceKind::MemberAccess("Azure::Core::Http.Request.GetBodyStream"),
        taint_label: "user_input",
        description: "CodeQL source: Azure::Core::Http.Request.GetBodyStream (kind: manual)",
    },
];

static AZURE_CORE_HTTP_GEN_SINKS: &[SinkDef] = &[];

static AZURE_CORE_HTTP_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AZURE_CORE_HTTP_GEN_IMPORTS: &[&str] = &["Azure::Core::Http"];

pub static AZURE_CORE_HTTP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "azure::core::http_generated",
    description: "Generated profile for Azure::Core::Http from CodeQL/Pysa",
    detect_imports: AZURE_CORE_HTTP_GEN_IMPORTS,
    sources: AZURE_CORE_HTTP_GEN_SOURCES,
    sinks: AZURE_CORE_HTTP_GEN_SINKS,
    sanitizers: AZURE_CORE_HTTP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
