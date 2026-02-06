//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_COLLECTIONS_BTREE_MAP_BTREEMAP_AS_LOG_KV_SOURCE_SOURCE_GET_GEN_SOURCES:
    &[SourceDef] = &[];

static ALLOC_COLLECTIONS_BTREE_MAP_BTREEMAP_AS_LOG_KV_SOURCE_SOURCE_GET_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "<alloc::collections::btree::map::BTreeMap as log::kv::source::Source>::get.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    },
];

static ALLOC_COLLECTIONS_BTREE_MAP_BTREEMAP_AS_LOG_KV_SOURCE_SOURCE_GET_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static ALLOC_COLLECTIONS_BTREE_MAP_BTREEMAP_AS_LOG_KV_SOURCE_SOURCE_GET_GEN_IMPORTS: &[&str] =
    &["<alloc::collections::btree::map::BTreeMap as log::kv::source::Source>::get"];

pub static ALLOC_COLLECTIONS_BTREE_MAP_BTREEMAP_AS_LOG_KV_SOURCE_SOURCE_GET_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<alloc::collections::btree::map::btreemap as log::kv::source::source>::get_generated",
    description: "Generated profile for <alloc::collections::btree::map::BTreeMap as log::kv::source::Source>::get from CodeQL/Pysa",
    detect_imports: ALLOC_COLLECTIONS_BTREE_MAP_BTREEMAP_AS_LOG_KV_SOURCE_SOURCE_GET_GEN_IMPORTS,
    sources: ALLOC_COLLECTIONS_BTREE_MAP_BTREEMAP_AS_LOG_KV_SOURCE_SOURCE_GET_GEN_SOURCES,
    sinks: ALLOC_COLLECTIONS_BTREE_MAP_BTREEMAP_AS_LOG_KV_SOURCE_SOURCE_GET_GEN_SINKS,
    sanitizers: ALLOC_COLLECTIONS_BTREE_MAP_BTREEMAP_AS_LOG_KV_SOURCE_SOURCE_GET_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
