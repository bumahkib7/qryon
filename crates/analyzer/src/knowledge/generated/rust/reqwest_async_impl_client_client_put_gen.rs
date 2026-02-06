//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REQWEST_ASYNC_IMPL_CLIENT_CLIENT_PUT_GEN_SOURCES: &[SourceDef] = &[];

static REQWEST_ASYNC_IMPL_CLIENT_CLIENT_PUT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<reqwest::async_impl::client::Client>::put.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-request-url",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: request-url)",
    cwe: Some("CWE-74"),
}];

static REQWEST_ASYNC_IMPL_CLIENT_CLIENT_PUT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REQWEST_ASYNC_IMPL_CLIENT_CLIENT_PUT_GEN_IMPORTS: &[&str] =
    &["<reqwest::async_impl::client::Client>::put"];

pub static REQWEST_ASYNC_IMPL_CLIENT_CLIENT_PUT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<reqwest::async_impl::client::client>::put_generated",
    description: "Generated profile for <reqwest::async_impl::client::Client>::put from CodeQL/Pysa",
    detect_imports: REQWEST_ASYNC_IMPL_CLIENT_CLIENT_PUT_GEN_IMPORTS,
    sources: REQWEST_ASYNC_IMPL_CLIENT_CLIENT_PUT_GEN_SOURCES,
    sinks: REQWEST_ASYNC_IMPL_CLIENT_CLIENT_PUT_GEN_SINKS,
    sanitizers: REQWEST_ASYNC_IMPL_CLIENT_CLIENT_PUT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
