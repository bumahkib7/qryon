//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AXIOS_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "axios.Member[interceptors].Member[response].Member[use].Argument[0].Parameter[0]",
    pattern: SourceKind::MemberAccess("interceptors.response.use.Parameter[0]"),
    taint_label: "user_input",
    description: "CodeQL source: Member[interceptors].Member[response].Member[use].Argument[0].Parameter[0] (kind: response)",
}];

static AXIOS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "axios.Member[interceptors].Member[request].Member[use].Argument[0].Parameter[0].Member[url]",
    pattern: SinkKind::FunctionCall("interceptors.request.use.Parameter[0].url"),
    rule_id: "javascript/gen-request-forgery",
    severity: Severity::Critical,
    description: "CodeQL sink: Member[interceptors].Member[request].Member[use].Argument[0].Parameter[0].Member[url] (kind: request-forgery)",
    cwe: Some("CWE-918"),
}];

static AXIOS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AXIOS_GEN_IMPORTS: &[&str] = &["axios"];

pub static AXIOS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "axios_generated",
    description: "Generated profile for axios from CodeQL/Pysa",
    detect_imports: AXIOS_GEN_IMPORTS,
    sources: AXIOS_GEN_SOURCES,
    sinks: AXIOS_GEN_SINKS,
    sanitizers: AXIOS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
