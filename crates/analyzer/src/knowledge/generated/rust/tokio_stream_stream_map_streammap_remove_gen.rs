//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_STREAM_STREAM_MAP_STREAMMAP_REMOVE_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_STREAM_STREAM_MAP_STREAMMAP_REMOVE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio_stream::stream_map::StreamMap>::remove.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[self] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_STREAM_STREAM_MAP_STREAMMAP_REMOVE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_STREAM_STREAM_MAP_STREAMMAP_REMOVE_GEN_IMPORTS: &[&str] =
    &["<tokio_stream::stream_map::StreamMap>::remove"];

pub static TOKIO_STREAM_STREAM_MAP_STREAMMAP_REMOVE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio_stream::stream_map::streammap>::remove_generated",
        description: "Generated profile for <tokio_stream::stream_map::StreamMap>::remove from CodeQL/Pysa",
        detect_imports: TOKIO_STREAM_STREAM_MAP_STREAMMAP_REMOVE_GEN_IMPORTS,
        sources: TOKIO_STREAM_STREAM_MAP_STREAMMAP_REMOVE_GEN_SOURCES,
        sinks: TOKIO_STREAM_STREAM_MAP_STREAMMAP_REMOVE_GEN_SINKS,
        sanitizers: TOKIO_STREAM_STREAM_MAP_STREAMMAP_REMOVE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
