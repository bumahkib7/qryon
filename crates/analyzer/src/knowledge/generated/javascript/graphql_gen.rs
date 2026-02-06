//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GRAPHQL_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "graphql.Member[GraphQLObjectType].Argument[0].Member[fields].AnyMember.Member[resolve].Parameter[1]",
    pattern: SourceKind::MemberAccess("GraphQLObjectType.fields.AnyMember.resolve.Parameter[1]"),
    taint_label: "user_input",
    description: "CodeQL source: Member[GraphQLObjectType].Argument[0].Member[fields].AnyMember.Member[resolve].Parameter[1] (kind: remote)",
}];

static GRAPHQL_GEN_SINKS: &[SinkDef] = &[];

static GRAPHQL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GRAPHQL_GEN_IMPORTS: &[&str] = &["graphql"];

pub static GRAPHQL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "graphql_generated",
    description: "Generated profile for graphql from CodeQL/Pysa",
    detect_imports: GRAPHQL_GEN_IMPORTS,
    sources: GRAPHQL_GEN_SOURCES,
    sinks: GRAPHQL_GEN_SINKS,
    sanitizers: GRAPHQL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
