//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TOKIO_UTIL_SHARDED_LIST_SHARDEDLIST_NEW_GEN_SOURCES: &[SourceDef] = &[];

static TOKIO_UTIL_SHARDED_LIST_SHARDEDLIST_NEW_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<tokio::util::sharded_list::ShardedList>::new.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static TOKIO_UTIL_SHARDED_LIST_SHARDEDLIST_NEW_GEN_SANITIZERS: &[SanitizerDef] = &[];

static TOKIO_UTIL_SHARDED_LIST_SHARDEDLIST_NEW_GEN_IMPORTS: &[&str] =
    &["<tokio::util::sharded_list::ShardedList>::new"];

pub static TOKIO_UTIL_SHARDED_LIST_SHARDEDLIST_NEW_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<tokio::util::sharded_list::shardedlist>::new_generated",
        description: "Generated profile for <tokio::util::sharded_list::ShardedList>::new from CodeQL/Pysa",
        detect_imports: TOKIO_UTIL_SHARDED_LIST_SHARDEDLIST_NEW_GEN_IMPORTS,
        sources: TOKIO_UTIL_SHARDED_LIST_SHARDEDLIST_NEW_GEN_SOURCES,
        sinks: TOKIO_UTIL_SHARDED_LIST_SHARDEDLIST_NEW_GEN_SINKS,
        sanitizers: TOKIO_UTIL_SHARDED_LIST_SHARDEDLIST_NEW_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
