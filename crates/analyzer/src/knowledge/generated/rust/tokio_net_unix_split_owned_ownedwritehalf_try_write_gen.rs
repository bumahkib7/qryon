//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_NET_UNIX_SPLIT_OWNED_OWNEDWRITEHALF_TRY_WRITE_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_NET_UNIX_SPLIT_OWNED_OWNEDWRITEHALF_TRY_WRITE_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::net::unix::split_owned::OwnedWriteHalf>::try_write.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_NET_UNIX_SPLIT_OWNED_OWNEDWRITEHALF_TRY_WRITE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_NET_UNIX_SPLIT_OWNED_OWNEDWRITEHALF_TRY_WRITE_GEN_IMPORTS: &[&str] =
    &["<tokio::net::unix::split_owned::OwnedWriteHalf>::try_write"];

pub static TOKIO_NET_UNIX_SPLIT_OWNED_OWNEDWRITEHALF_TRY_WRITE_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::net::unix::split_owned::ownedwritehalf>::try_write_generated",
        description: "Generated profile for <tokio::net::unix::split_owned::OwnedWriteHalf>::try_write from CodeQL/Pysa",
        detect_imports: TOKIO_NET_UNIX_SPLIT_OWNED_OWNEDWRITEHALF_TRY_WRITE_GEN_IMPORTS,
        sources: TOKIO_NET_UNIX_SPLIT_OWNED_OWNEDWRITEHALF_TRY_WRITE_GEN_SOURCES,
        sinks: TOKIO_NET_UNIX_SPLIT_OWNED_OWNEDWRITEHALF_TRY_WRITE_GEN_SINKS,
        sanitizers: TOKIO_NET_UNIX_SPLIT_OWNED_OWNEDWRITEHALF_TRY_WRITE_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
