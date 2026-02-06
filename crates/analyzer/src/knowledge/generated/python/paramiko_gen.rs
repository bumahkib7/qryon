//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PARAMIKO_GEN_SOURCES: &[SourceDef] = &[];

static PARAMIKO_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "paramiko.proxy_command.ProxyCommand.__init__",
        pattern: SinkKind::FunctionCall("paramiko.proxy_command.ProxyCommand.__init__"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: paramiko.proxy_command.ProxyCommand.__init__ (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "paramiko.channel.Channel.exec_command",
        pattern: SinkKind::FunctionCall("paramiko.channel.Channel.exec_command"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: paramiko.channel.Channel.exec_command (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
];

static PARAMIKO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PARAMIKO_GEN_IMPORTS: &[&str] = &["paramiko"];

pub static PARAMIKO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "paramiko_generated",
    description: "Generated profile for paramiko from CodeQL/Pysa",
    detect_imports: PARAMIKO_GEN_IMPORTS,
    sources: PARAMIKO_GEN_SOURCES,
    sinks: PARAMIKO_GEN_SINKS,
    sanitizers: PARAMIKO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
