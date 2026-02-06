//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_STREAM_STREAM_EXT_CHUNKS_TIMEOUT_CHUNKSTIMEOUT_NEW_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_STREAM_STREAM_EXT_CHUNKS_TIMEOUT_CHUNKSTIMEOUT_NEW_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<tokio_stream::stream_ext::chunks_timeout::ChunksTimeout>::new.Argument[1]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[1] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    }];

static TOKIO_STREAM_STREAM_EXT_CHUNKS_TIMEOUT_CHUNKSTIMEOUT_NEW_GEN_SANITIZERS: &[SanitizerDef] =
    &[];

static TOKIO_STREAM_STREAM_EXT_CHUNKS_TIMEOUT_CHUNKSTIMEOUT_NEW_GEN_IMPORTS: &[&str] =
    &["<tokio_stream::stream_ext::chunks_timeout::ChunksTimeout>::new"];

pub static TOKIO_STREAM_STREAM_EXT_CHUNKS_TIMEOUT_CHUNKSTIMEOUT_NEW_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio_stream::stream_ext::chunks_timeout::chunkstimeout>::new_generated",
        description: "Generated profile for <tokio_stream::stream_ext::chunks_timeout::ChunksTimeout>::new from CodeQL/Pysa",
        detect_imports: TOKIO_STREAM_STREAM_EXT_CHUNKS_TIMEOUT_CHUNKSTIMEOUT_NEW_GEN_IMPORTS,
        sources: TOKIO_STREAM_STREAM_EXT_CHUNKS_TIMEOUT_CHUNKSTIMEOUT_NEW_GEN_SOURCES,
        sinks: TOKIO_STREAM_STREAM_EXT_CHUNKS_TIMEOUT_CHUNKSTIMEOUT_NEW_GEN_SINKS,
        sanitizers: TOKIO_STREAM_STREAM_EXT_CHUNKS_TIMEOUT_CHUNKSTIMEOUT_NEW_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
