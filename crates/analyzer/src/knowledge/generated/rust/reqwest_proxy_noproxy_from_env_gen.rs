//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REQWEST_PROXY_NOPROXY_FROM_ENV_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "<reqwest::proxy::NoProxy>::from_env.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "env_input",
    description: "CodeQL source: ReturnValue (kind: environment)",
}];

static REQWEST_PROXY_NOPROXY_FROM_ENV_GEN_SINKS: &[SinkDef] = &[];

static REQWEST_PROXY_NOPROXY_FROM_ENV_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REQWEST_PROXY_NOPROXY_FROM_ENV_GEN_IMPORTS: &[&str] =
    &["<reqwest::proxy::NoProxy>::from_env"];

pub static REQWEST_PROXY_NOPROXY_FROM_ENV_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<reqwest::proxy::noproxy>::from_env_generated",
    description: "Generated profile for <reqwest::proxy::NoProxy>::from_env from CodeQL/Pysa",
    detect_imports: REQWEST_PROXY_NOPROXY_FROM_ENV_GEN_IMPORTS,
    sources: REQWEST_PROXY_NOPROXY_FROM_ENV_GEN_SOURCES,
    sinks: REQWEST_PROXY_NOPROXY_FROM_ENV_GEN_SINKS,
    sanitizers: REQWEST_PROXY_NOPROXY_FROM_ENV_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
