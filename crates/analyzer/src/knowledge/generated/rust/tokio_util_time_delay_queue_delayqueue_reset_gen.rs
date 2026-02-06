//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_UTIL_TIME_DELAY_QUEUE_DELAYQUEUE_RESET_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_UTIL_TIME_DELAY_QUEUE_DELAYQUEUE_RESET_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<tokio_util::time::delay_queue::DelayQueue>::reset.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[0] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
    SinkDef {
        name: "<tokio_util::time::delay_queue::DelayQueue>::reset.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-log-injection",
        severity: Severity::Warning,
        description: "CodeQL sink: Argument[self] (kind: log-injection)",
        cwe: Some("CWE-117"),
    },
];

static TOKIO_UTIL_TIME_DELAY_QUEUE_DELAYQUEUE_RESET_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_UTIL_TIME_DELAY_QUEUE_DELAYQUEUE_RESET_GEN_IMPORTS: &[&str] =
    &["<tokio_util::time::delay_queue::DelayQueue>::reset"];

pub static TOKIO_UTIL_TIME_DELAY_QUEUE_DELAYQUEUE_RESET_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio_util::time::delay_queue::delayqueue>::reset_generated",
        description: "Generated profile for <tokio_util::time::delay_queue::DelayQueue>::reset from CodeQL/Pysa",
        detect_imports: TOKIO_UTIL_TIME_DELAY_QUEUE_DELAYQUEUE_RESET_GEN_IMPORTS,
        sources: TOKIO_UTIL_TIME_DELAY_QUEUE_DELAYQUEUE_RESET_GEN_SOURCES,
        sinks: TOKIO_UTIL_TIME_DELAY_QUEUE_DELAYQUEUE_RESET_GEN_SINKS,
        sanitizers: TOKIO_UTIL_TIME_DELAY_QUEUE_DELAYQUEUE_RESET_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
