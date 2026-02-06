//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REQWEST_ASYNC_IMPL_CLIENT_CLIENTBUILDER_BUILD_GEN_SOURCES: &[SourceDef] = &[];

static REQWEST_ASYNC_IMPL_CLIENT_CLIENTBUILDER_BUILD_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<reqwest::async_impl::client::ClientBuilder>::build.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-disable-certificate",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: disable-certificate)",
    cwe: Some("CWE-74"),
}];

static REQWEST_ASYNC_IMPL_CLIENT_CLIENTBUILDER_BUILD_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REQWEST_ASYNC_IMPL_CLIENT_CLIENTBUILDER_BUILD_GEN_IMPORTS: &[&str] =
    &["<reqwest::async_impl::client::ClientBuilder>::build"];

pub static REQWEST_ASYNC_IMPL_CLIENT_CLIENTBUILDER_BUILD_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<reqwest::async_impl::client::clientbuilder>::build_generated",
        description: "Generated profile for <reqwest::async_impl::client::ClientBuilder>::build from CodeQL/Pysa",
        detect_imports: REQWEST_ASYNC_IMPL_CLIENT_CLIENTBUILDER_BUILD_GEN_IMPORTS,
        sources: REQWEST_ASYNC_IMPL_CLIENT_CLIENTBUILDER_BUILD_GEN_SOURCES,
        sinks: REQWEST_ASYNC_IMPL_CLIENT_CLIENTBUILDER_BUILD_GEN_SINKS,
        sanitizers: REQWEST_ASYNC_IMPL_CLIENT_CLIENTBUILDER_BUILD_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
