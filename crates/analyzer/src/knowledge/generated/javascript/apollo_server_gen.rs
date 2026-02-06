//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static APOLLO_SERVER_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "@apollo/server.Member[ApolloServer,ApolloServerBase].Argument[0].AnyMember.AnyMember.AnyMember.Parameter[1]",
    pattern: SourceKind::MemberAccess(
        "ApolloServer,ApolloServerBase.AnyMember.AnyMember.AnyMember.Parameter[1]",
    ),
    taint_label: "user_input",
    description: "CodeQL source: Member[ApolloServer,ApolloServerBase].Argument[0].AnyMember.AnyMember.AnyMember.Parameter[1] (kind: remote)",
}];

static APOLLO_SERVER_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "@apollo/server.Member[gql].Argument[0]",
        pattern: SinkKind::FunctionCall("gql"),
        rule_id: "javascript/gen-sql-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Member[gql].Argument[0] (kind: sql-injection)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "@apollo/server.Member[ApolloServer,ApolloServerBase].Argument[0].Member[cors].Member[origin]",
        pattern: SinkKind::FunctionCall("ApolloServer,ApolloServerBase.cors.origin"),
        rule_id: "javascript/gen-cors-origin",
        severity: Severity::Error,
        description: "CodeQL sink: Member[ApolloServer,ApolloServerBase].Argument[0].Member[cors].Member[origin] (kind: cors-origin)",
        cwe: Some("CWE-74"),
    },
];

static APOLLO_SERVER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static APOLLO_SERVER_GEN_IMPORTS: &[&str] = &["@apollo/server"];

pub static APOLLO_SERVER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "@apollo_server_generated",
    description: "Generated profile for @apollo/server from CodeQL/Pysa",
    detect_imports: APOLLO_SERVER_GEN_IMPORTS,
    sources: APOLLO_SERVER_GEN_SOURCES,
    sinks: APOLLO_SERVER_GEN_SINKS,
    sanitizers: APOLLO_SERVER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
