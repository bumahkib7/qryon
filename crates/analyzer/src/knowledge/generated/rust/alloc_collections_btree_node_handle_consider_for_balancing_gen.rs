//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ALLOC_COLLECTIONS_BTREE_NODE_HANDLE_CONSIDER_FOR_BALANCING_GEN_SOURCES: &[SourceDef] = &[];

static ALLOC_COLLECTIONS_BTREE_NODE_HANDLE_CONSIDER_FOR_BALANCING_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<alloc::collections::btree::node::Handle>::consider_for_balancing.Argument[self]",
        pattern: SinkKind::FunctionCall("Argument[self]"),
        rule_id: "rust/gen-pointer-access",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[self] (kind: pointer-access)",
        cwe: Some("CWE-74"),
    }];

static ALLOC_COLLECTIONS_BTREE_NODE_HANDLE_CONSIDER_FOR_BALANCING_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static ALLOC_COLLECTIONS_BTREE_NODE_HANDLE_CONSIDER_FOR_BALANCING_GEN_IMPORTS: &[&str] =
    &["<alloc::collections::btree::node::Handle>::consider_for_balancing"];

pub static ALLOC_COLLECTIONS_BTREE_NODE_HANDLE_CONSIDER_FOR_BALANCING_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<alloc::collections::btree::node::handle>::consider_for_balancing_generated",
    description: "Generated profile for <alloc::collections::btree::node::Handle>::consider_for_balancing from CodeQL/Pysa",
    detect_imports: ALLOC_COLLECTIONS_BTREE_NODE_HANDLE_CONSIDER_FOR_BALANCING_GEN_IMPORTS,
    sources: ALLOC_COLLECTIONS_BTREE_NODE_HANDLE_CONSIDER_FOR_BALANCING_GEN_SOURCES,
    sinks: ALLOC_COLLECTIONS_BTREE_NODE_HANDLE_CONSIDER_FOR_BALANCING_GEN_SINKS,
    sanitizers: ALLOC_COLLECTIONS_BTREE_NODE_HANDLE_CONSIDER_FOR_BALANCING_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
