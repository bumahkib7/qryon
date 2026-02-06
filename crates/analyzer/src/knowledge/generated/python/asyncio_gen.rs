//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ASYNCIO_GEN_SOURCES: &[SourceDef] = &[];

static ASYNCIO_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "asyncio.events.AbstractEventLoop.subprocess_exec",
        pattern: SinkKind::FunctionCall("asyncio.events.AbstractEventLoop.subprocess_exec"),
        rule_id: "python/gen-pysa-execargsink",
        severity: Severity::Error,
        description: "Pysa sink: asyncio.events.AbstractEventLoop.subprocess_exec (kind: ExecArgSink)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "asyncio.events.AbstractEventLoop.subprocess_shell",
        pattern: SinkKind::FunctionCall("asyncio.events.AbstractEventLoop.subprocess_shell"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: asyncio.events.AbstractEventLoop.subprocess_shell (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
];

static ASYNCIO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ASYNCIO_GEN_IMPORTS: &[&str] = &["asyncio"];

pub static ASYNCIO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "asyncio_generated",
    description: "Generated profile for asyncio from CodeQL/Pysa",
    detect_imports: ASYNCIO_GEN_IMPORTS,
    sources: ASYNCIO_GEN_SOURCES,
    sinks: ASYNCIO_GEN_SINKS,
    sanitizers: ASYNCIO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
