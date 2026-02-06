//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PEXPECT_GEN_SOURCES: &[SourceDef] = &[];

static PEXPECT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "pexpect.spawn.sendline",
        pattern: SinkKind::FunctionCall("pexpect.spawn.sendline"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: pexpect.spawn.sendline (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "pexpect.spawn.send",
        pattern: SinkKind::FunctionCall("pexpect.spawn.send"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: pexpect.spawn.send (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
];

static PEXPECT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PEXPECT_GEN_IMPORTS: &[&str] = &["pexpect"];

pub static PEXPECT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "pexpect_generated",
    description: "Generated profile for pexpect from CodeQL/Pysa",
    detect_imports: PEXPECT_GEN_IMPORTS,
    sources: PEXPECT_GEN_SOURCES,
    sinks: PEXPECT_GEN_SINKS,
    sanitizers: PEXPECT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
