//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SIGNAL_NOTIFY_BOTH_SUPPORT_SIGNAL_SEND_SIGNAL_GEN_SOURCES: &[SourceDef] = &[];

static SIGNAL_NOTIFY_BOTH_SUPPORT_SIGNAL_SEND_SIGNAL_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "signal_notify_both::support::signal::send_signal.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static SIGNAL_NOTIFY_BOTH_SUPPORT_SIGNAL_SEND_SIGNAL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SIGNAL_NOTIFY_BOTH_SUPPORT_SIGNAL_SEND_SIGNAL_GEN_IMPORTS: &[&str] =
    &["signal_notify_both::support::signal::send_signal"];

pub static SIGNAL_NOTIFY_BOTH_SUPPORT_SIGNAL_SEND_SIGNAL_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "signal_notify_both::support::signal::send_signal_generated",
        description: "Generated profile for signal_notify_both::support::signal::send_signal from CodeQL/Pysa",
        detect_imports: SIGNAL_NOTIFY_BOTH_SUPPORT_SIGNAL_SEND_SIGNAL_GEN_IMPORTS,
        sources: SIGNAL_NOTIFY_BOTH_SUPPORT_SIGNAL_SEND_SIGNAL_GEN_SOURCES,
        sinks: SIGNAL_NOTIFY_BOTH_SUPPORT_SIGNAL_SEND_SIGNAL_GEN_SINKS,
        sanitizers: SIGNAL_NOTIFY_BOTH_SUPPORT_SIGNAL_SEND_SIGNAL_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
