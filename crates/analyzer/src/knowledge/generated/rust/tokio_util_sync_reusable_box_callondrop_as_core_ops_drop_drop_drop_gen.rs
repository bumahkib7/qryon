//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_UTIL_SYNC_REUSABLE_BOX_CALLONDROP_AS_CORE_OPS_DROP_DROP_DROP_GEN_SOURCES:
    &[SourceDef] = &[];

static TOKIO_UTIL_SYNC_REUSABLE_BOX_CALLONDROP_AS_CORE_OPS_DROP_DROP_DROP_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<tokio_util::sync::reusable_box::CallOnDrop as core::ops::drop::Drop>::drop.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    },
];

static TOKIO_UTIL_SYNC_REUSABLE_BOX_CALLONDROP_AS_CORE_OPS_DROP_DROP_DROP_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static TOKIO_UTIL_SYNC_REUSABLE_BOX_CALLONDROP_AS_CORE_OPS_DROP_DROP_DROP_GEN_IMPORTS: &[&str] =
    &["<tokio_util::sync::reusable_box::CallOnDrop as core::ops::drop::Drop>::drop"];

pub static TOKIO_UTIL_SYNC_REUSABLE_BOX_CALLONDROP_AS_CORE_OPS_DROP_DROP_DROP_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<tokio_util::sync::reusable_box::callondrop as core::ops::drop::drop>::drop_generated",
    description: "Generated profile for <tokio_util::sync::reusable_box::CallOnDrop as core::ops::drop::Drop>::drop from CodeQL/Pysa",
    detect_imports: TOKIO_UTIL_SYNC_REUSABLE_BOX_CALLONDROP_AS_CORE_OPS_DROP_DROP_DROP_GEN_IMPORTS,
    sources: TOKIO_UTIL_SYNC_REUSABLE_BOX_CALLONDROP_AS_CORE_OPS_DROP_DROP_DROP_GEN_SOURCES,
    sinks: TOKIO_UTIL_SYNC_REUSABLE_BOX_CALLONDROP_AS_CORE_OPS_DROP_DROP_DROP_GEN_SINKS,
    sanitizers: TOKIO_UTIL_SYNC_REUSABLE_BOX_CALLONDROP_AS_CORE_OPS_DROP_DROP_DROP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
