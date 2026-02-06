//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static OS_EXEC_GEN_SOURCES: &[SourceDef] = &[];

static OS_EXEC_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "os/exec.Command",
        pattern: SinkKind::FunctionCall("os/exec.Command"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: os/exec..Command (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "os/exec.CommandContext",
        pattern: SinkKind::FunctionCall("os/exec.CommandContext"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: os/exec..CommandContext (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static OS_EXEC_GEN_SANITIZERS: &[SanitizerDef] = &[];

static OS_EXEC_GEN_IMPORTS: &[&str] = &["os/exec"];

pub static OS_EXEC_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "os_exec_generated",
    description: "Generated profile for os/exec from CodeQL/Pysa",
    detect_imports: OS_EXEC_GEN_IMPORTS,
    sources: OS_EXEC_GEN_SOURCES,
    sinks: OS_EXEC_GEN_SINKS,
    sanitizers: OS_EXEC_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
