//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_IO_BLOCKING_BUF_WITH_CAPACITY_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_IO_BLOCKING_BUF_WITH_CAPACITY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::io::blocking::Buf>::with_capacity.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static TOKIO_IO_BLOCKING_BUF_WITH_CAPACITY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_IO_BLOCKING_BUF_WITH_CAPACITY_GEN_IMPORTS: &[&str] =
    &["<tokio::io::blocking::Buf>::with_capacity"];

pub static TOKIO_IO_BLOCKING_BUF_WITH_CAPACITY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<tokio::io::blocking::buf>::with_capacity_generated",
    description: "Generated profile for <tokio::io::blocking::Buf>::with_capacity from CodeQL/Pysa",
    detect_imports: TOKIO_IO_BLOCKING_BUF_WITH_CAPACITY_GEN_IMPORTS,
    sources: TOKIO_IO_BLOCKING_BUF_WITH_CAPACITY_GEN_SOURCES,
    sinks: TOKIO_IO_BLOCKING_BUF_WITH_CAPACITY_GEN_SINKS,
    sanitizers: TOKIO_IO_BLOCKING_BUF_WITH_CAPACITY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
