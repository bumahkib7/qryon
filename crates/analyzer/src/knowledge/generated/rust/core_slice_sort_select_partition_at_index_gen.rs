//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CORE_SLICE_SORT_SELECT_PARTITION_AT_INDEX_GEN_SOURCES: &[SourceDef] = &[];

static CORE_SLICE_SORT_SELECT_PARTITION_AT_INDEX_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "core::slice::sort::select::partition_at_index.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[1] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static CORE_SLICE_SORT_SELECT_PARTITION_AT_INDEX_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CORE_SLICE_SORT_SELECT_PARTITION_AT_INDEX_GEN_IMPORTS: &[&str] =
    &["core::slice::sort::select::partition_at_index"];

pub static CORE_SLICE_SORT_SELECT_PARTITION_AT_INDEX_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "core::slice::sort::select::partition_at_index_generated",
        description: "Generated profile for core::slice::sort::select::partition_at_index from CodeQL/Pysa",
        detect_imports: CORE_SLICE_SORT_SELECT_PARTITION_AT_INDEX_GEN_IMPORTS,
        sources: CORE_SLICE_SORT_SELECT_PARTITION_AT_INDEX_GEN_SOURCES,
        sinks: CORE_SLICE_SORT_SELECT_PARTITION_AT_INDEX_GEN_SINKS,
        sanitizers: CORE_SLICE_SORT_SELECT_PARTITION_AT_INDEX_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
