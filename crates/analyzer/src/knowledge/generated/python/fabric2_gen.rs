//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FABRIC2_GEN_SOURCES: &[SourceDef] = &[];

static FABRIC2_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "fabric2.connection.Connection.local",
        pattern: SinkKind::FunctionCall("fabric2.connection.Connection.local"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: fabric2.connection.Connection.local (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "fabric2.connection.Connection.run",
        pattern: SinkKind::FunctionCall("fabric2.connection.Connection.run"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: fabric2.connection.Connection.run (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "fabric2.connection.Connection.sudo",
        pattern: SinkKind::FunctionCall("fabric2.connection.Connection.sudo"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: fabric2.connection.Connection.sudo (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "fabric2.transfer.Transfer.get",
        pattern: SinkKind::FunctionCall("fabric2.transfer.Transfer.get"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: fabric2.transfer.Transfer.get (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "fabric2.transfer.Transfer.put",
        pattern: SinkKind::FunctionCall("fabric2.transfer.Transfer.put"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: fabric2.transfer.Transfer.put (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
];

static FABRIC2_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FABRIC2_GEN_IMPORTS: &[&str] = &["fabric2"];

pub static FABRIC2_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "fabric2_generated",
    description: "Generated profile for fabric2 from CodeQL/Pysa",
    detect_imports: FABRIC2_GEN_IMPORTS,
    sources: FABRIC2_GEN_SOURCES,
    sinks: FABRIC2_GEN_SINKS,
    sanitizers: FABRIC2_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
