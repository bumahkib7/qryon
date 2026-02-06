//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SYSCALL_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "syscall.Environ",
        pattern: SourceKind::MemberAccess("syscall.Environ"),
        taint_label: "user_input",
        description: "CodeQL source: syscall..Environ (kind: manual)",
    },
    SourceDef {
        name: "syscall.Getenv",
        pattern: SourceKind::MemberAccess("syscall.Getenv"),
        taint_label: "user_input",
        description: "CodeQL source: syscall..Getenv (kind: manual)",
    },
];

static SYSCALL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "syscall.Exec",
        pattern: SinkKind::FunctionCall("syscall.Exec"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: syscall..Exec (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "syscall.ForkExec",
        pattern: SinkKind::FunctionCall("syscall.ForkExec"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: syscall..ForkExec (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "syscall.StartProcess",
        pattern: SinkKind::FunctionCall("syscall.StartProcess"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: syscall..StartProcess (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "syscall.CreateProcess",
        pattern: SinkKind::FunctionCall("syscall.CreateProcess"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: syscall..CreateProcess (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "syscall.CreateProcessAsUser",
        pattern: SinkKind::FunctionCall("syscall.CreateProcessAsUser"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: syscall..CreateProcessAsUser (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static SYSCALL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SYSCALL_GEN_IMPORTS: &[&str] = &["syscall"];

pub static SYSCALL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "syscall_generated",
    description: "Generated profile for syscall from CodeQL/Pysa",
    detect_imports: SYSCALL_GEN_IMPORTS,
    sources: SYSCALL_GEN_SOURCES,
    sinks: SYSCALL_GEN_SINKS,
    sanitizers: SYSCALL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
