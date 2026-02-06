//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLAP_BUILDER_UTIL_GRAPH_CHILDGRAPH_WITH_CAPACITY_GEN_SOURCES: &[SourceDef] = &[];

static CLAP_BUILDER_UTIL_GRAPH_CHILDGRAPH_WITH_CAPACITY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<clap_builder::util::graph::ChildGraph>::with_capacity.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static CLAP_BUILDER_UTIL_GRAPH_CHILDGRAPH_WITH_CAPACITY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CLAP_BUILDER_UTIL_GRAPH_CHILDGRAPH_WITH_CAPACITY_GEN_IMPORTS: &[&str] =
    &["<clap_builder::util::graph::ChildGraph>::with_capacity"];

pub static CLAP_BUILDER_UTIL_GRAPH_CHILDGRAPH_WITH_CAPACITY_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<clap_builder::util::graph::childgraph>::with_capacity_generated",
        description: "Generated profile for <clap_builder::util::graph::ChildGraph>::with_capacity from CodeQL/Pysa",
        detect_imports: CLAP_BUILDER_UTIL_GRAPH_CHILDGRAPH_WITH_CAPACITY_GEN_IMPORTS,
        sources: CLAP_BUILDER_UTIL_GRAPH_CHILDGRAPH_WITH_CAPACITY_GEN_SOURCES,
        sinks: CLAP_BUILDER_UTIL_GRAPH_CHILDGRAPH_WITH_CAPACITY_GEN_SINKS,
        sanitizers: CLAP_BUILDER_UTIL_GRAPH_CHILDGRAPH_WITH_CAPACITY_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
