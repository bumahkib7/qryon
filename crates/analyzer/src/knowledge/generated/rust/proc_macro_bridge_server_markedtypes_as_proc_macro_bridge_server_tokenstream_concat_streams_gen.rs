//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PROC_MACRO_BRIDGE_SERVER_MARKEDTYPES_AS_PROC_MACRO_BRIDGE_SERVER_TOKENSTREAM_CONCAT_STREAMS_GEN_SOURCES: &[SourceDef] = &[
];

static PROC_MACRO_BRIDGE_SERVER_MARKEDTYPES_AS_PROC_MACRO_BRIDGE_SERVER_TOKENSTREAM_CONCAT_STREAMS_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<proc_macro::bridge::server::MarkedTypes as proc_macro::bridge::server::TokenStream>::concat_streams.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[1] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
];

static PROC_MACRO_BRIDGE_SERVER_MARKEDTYPES_AS_PROC_MACRO_BRIDGE_SERVER_TOKENSTREAM_CONCAT_STREAMS_GEN_SANITIZERS: &[SanitizerDef] = &[
];

static PROC_MACRO_BRIDGE_SERVER_MARKEDTYPES_AS_PROC_MACRO_BRIDGE_SERVER_TOKENSTREAM_CONCAT_STREAMS_GEN_IMPORTS: &[&str] = &[
    "<proc_macro::bridge::server::MarkedTypes as proc_macro::bridge::server::TokenStream>::concat_streams",
];

pub static PROC_MACRO_BRIDGE_SERVER_MARKEDTYPES_AS_PROC_MACRO_BRIDGE_SERVER_TOKENSTREAM_CONCAT_STREAMS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<proc_macro::bridge::server::markedtypes as proc_macro::bridge::server::tokenstream>::concat_streams_generated",
    description: "Generated profile for <proc_macro::bridge::server::MarkedTypes as proc_macro::bridge::server::TokenStream>::concat_streams from CodeQL/Pysa",
    detect_imports: PROC_MACRO_BRIDGE_SERVER_MARKEDTYPES_AS_PROC_MACRO_BRIDGE_SERVER_TOKENSTREAM_CONCAT_STREAMS_GEN_IMPORTS,
    sources: PROC_MACRO_BRIDGE_SERVER_MARKEDTYPES_AS_PROC_MACRO_BRIDGE_SERVER_TOKENSTREAM_CONCAT_STREAMS_GEN_SOURCES,
    sinks: PROC_MACRO_BRIDGE_SERVER_MARKEDTYPES_AS_PROC_MACRO_BRIDGE_SERVER_TOKENSTREAM_CONCAT_STREAMS_GEN_SINKS,
    sanitizers: PROC_MACRO_BRIDGE_SERVER_MARKEDTYPES_AS_PROC_MACRO_BRIDGE_SERVER_TOKENSTREAM_CONCAT_STREAMS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
