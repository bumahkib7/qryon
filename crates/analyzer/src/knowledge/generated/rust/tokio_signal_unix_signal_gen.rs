//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_SIGNAL_UNIX_SIGNAL_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_SIGNAL_UNIX_SIGNAL_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "tokio::signal::unix::signal.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_SIGNAL_UNIX_SIGNAL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_SIGNAL_UNIX_SIGNAL_GEN_IMPORTS: &[&str] = &["tokio::signal::unix::signal"];

pub static TOKIO_SIGNAL_UNIX_SIGNAL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "tokio::signal::unix::signal_generated",
    description: "Generated profile for tokio::signal::unix::signal from CodeQL/Pysa",
    detect_imports: TOKIO_SIGNAL_UNIX_SIGNAL_GEN_IMPORTS,
    sources: TOKIO_SIGNAL_UNIX_SIGNAL_GEN_SOURCES,
    sinks: TOKIO_SIGNAL_UNIX_SIGNAL_GEN_SINKS,
    sanitizers: TOKIO_SIGNAL_UNIX_SIGNAL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
