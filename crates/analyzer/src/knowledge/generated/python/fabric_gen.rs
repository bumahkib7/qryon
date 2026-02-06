//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FABRIC_GEN_SOURCES: &[SourceDef] = &[];

static FABRIC_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "fabric.operations.local",
        pattern: SinkKind::FunctionCall("fabric.operations.local"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.operations.local (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "fabric.operations.reboot",
        pattern: SinkKind::FunctionCall("fabric.operations.reboot"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.operations.reboot (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "fabric.operations.run",
        pattern: SinkKind::FunctionCall("fabric.operations.run"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.operations.run (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "fabric.operations.sudo",
        pattern: SinkKind::FunctionCall("fabric.operations.sudo"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.operations.sudo (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "fabric.connection.Connection.local",
        pattern: SinkKind::FunctionCall("fabric.connection.Connection.local"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.connection.Connection.local (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "fabric.connection.Connection.run",
        pattern: SinkKind::FunctionCall("fabric.connection.Connection.run"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.connection.Connection.run (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "fabric.connection.Connection.sudo",
        pattern: SinkKind::FunctionCall("fabric.connection.Connection.sudo"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.connection.Connection.sudo (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "fabric.operations.get",
        pattern: SinkKind::FunctionCall("fabric.operations.get"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.operations.get (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "fabric.operations.put",
        pattern: SinkKind::FunctionCall("fabric.operations.put"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.operations.put (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "fabric.transfer.Transfer.get",
        pattern: SinkKind::FunctionCall("fabric.transfer.Transfer.get"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.transfer.Transfer.get (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "fabric.transfer.Transfer.put",
        pattern: SinkKind::FunctionCall("fabric.transfer.Transfer.put"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: fabric.transfer.Transfer.put (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
];

static FABRIC_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FABRIC_GEN_IMPORTS: &[&str] = &["fabric"];

pub static FABRIC_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "fabric_generated",
    description: "Generated profile for fabric from CodeQL/Pysa",
    detect_imports: FABRIC_GEN_IMPORTS,
    sources: FABRIC_GEN_SOURCES,
    sinks: FABRIC_GEN_SINKS,
    sanitizers: FABRIC_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
