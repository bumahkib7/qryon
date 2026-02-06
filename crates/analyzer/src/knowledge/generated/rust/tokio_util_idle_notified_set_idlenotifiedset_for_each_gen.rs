//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_UTIL_IDLE_NOTIFIED_SET_IDLENOTIFIEDSET_FOR_EACH_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_UTIL_IDLE_NOTIFIED_SET_IDLENOTIFIEDSET_FOR_EACH_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::util::idle_notified_set::IdleNotifiedSet>::for_each.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static TOKIO_UTIL_IDLE_NOTIFIED_SET_IDLENOTIFIEDSET_FOR_EACH_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_UTIL_IDLE_NOTIFIED_SET_IDLENOTIFIEDSET_FOR_EACH_GEN_IMPORTS: &[&str] =
    &["<tokio::util::idle_notified_set::IdleNotifiedSet>::for_each"];

pub static TOKIO_UTIL_IDLE_NOTIFIED_SET_IDLENOTIFIEDSET_FOR_EACH_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::util::idle_notified_set::idlenotifiedset>::for_each_generated",
        description: "Generated profile for <tokio::util::idle_notified_set::IdleNotifiedSet>::for_each from CodeQL/Pysa",
        detect_imports: TOKIO_UTIL_IDLE_NOTIFIED_SET_IDLENOTIFIEDSET_FOR_EACH_GEN_IMPORTS,
        sources: TOKIO_UTIL_IDLE_NOTIFIED_SET_IDLENOTIFIEDSET_FOR_EACH_GEN_SOURCES,
        sinks: TOKIO_UTIL_IDLE_NOTIFIED_SET_IDLENOTIFIEDSET_FOR_EACH_GEN_SINKS,
        sanitizers: TOKIO_UTIL_IDLE_NOTIFIED_SET_IDLENOTIFIEDSET_FOR_EACH_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
