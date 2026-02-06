//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_RUNTIME_TASK_STATE_STATE_TRANSITION_TO_TERMINAL_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_RUNTIME_TASK_STATE_STATE_TRANSITION_TO_TERMINAL_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::runtime::task::state::State>::transition_to_terminal.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static TOKIO_RUNTIME_TASK_STATE_STATE_TRANSITION_TO_TERMINAL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_RUNTIME_TASK_STATE_STATE_TRANSITION_TO_TERMINAL_GEN_IMPORTS: &[&str] =
    &["<tokio::runtime::task::state::State>::transition_to_terminal"];

pub static TOKIO_RUNTIME_TASK_STATE_STATE_TRANSITION_TO_TERMINAL_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::runtime::task::state::state>::transition_to_terminal_generated",
        description: "Generated profile for <tokio::runtime::task::state::State>::transition_to_terminal from CodeQL/Pysa",
        detect_imports: TOKIO_RUNTIME_TASK_STATE_STATE_TRANSITION_TO_TERMINAL_GEN_IMPORTS,
        sources: TOKIO_RUNTIME_TASK_STATE_STATE_TRANSITION_TO_TERMINAL_GEN_SOURCES,
        sinks: TOKIO_RUNTIME_TASK_STATE_STATE_TRANSITION_TO_TERMINAL_GEN_SINKS,
        sanitizers: TOKIO_RUNTIME_TASK_STATE_STATE_TRANSITION_TO_TERMINAL_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
