//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STREAM_GEN_SOURCES: &[SourceDef] = &[];

static STREAM_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "stream",
    pattern: SinkKind::FunctionCall("stream"),
    rule_id: "python/gen-pysa-execdeserializationsink",
    severity: Severity::Error,
    description: "Pysa sink: stream (kind: ExecDeserializationSink)",
    cwe: Some("CWE-74"),
}];

static STREAM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STREAM_GEN_IMPORTS: &[&str] = &["stream"];

pub static STREAM_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "stream_generated",
    description: "Generated profile for stream from CodeQL/Pysa",
    detect_imports: STREAM_GEN_IMPORTS,
    sources: STREAM_GEN_SOURCES,
    sinks: STREAM_GEN_SINKS,
    sanitizers: STREAM_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
