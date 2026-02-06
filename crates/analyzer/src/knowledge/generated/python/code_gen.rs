//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CODE_GEN_SOURCES: &[SourceDef] = &[];

static CODE_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "code.compile_command",
        pattern: SinkKind::FunctionCall("code.compile_command"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: code.compile_command (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "code.InteractiveInterpreter.runsource",
        pattern: SinkKind::FunctionCall("code.InteractiveInterpreter.runsource"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: code.InteractiveInterpreter.runsource (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "code.InteractiveInterpreter.runcode",
        pattern: SinkKind::FunctionCall("code.InteractiveInterpreter.runcode"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: code.InteractiveInterpreter.runcode (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "code.InteractiveConsole.push",
        pattern: SinkKind::FunctionCall("code.InteractiveConsole.push"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: code.InteractiveConsole.push (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
];

static CODE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CODE_GEN_IMPORTS: &[&str] = &["code"];

pub static CODE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "code_generated",
    description: "Generated profile for code from CodeQL/Pysa",
    detect_imports: CODE_GEN_IMPORTS,
    sources: CODE_GEN_SOURCES,
    sinks: CODE_GEN_SINKS,
    sanitizers: CODE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
