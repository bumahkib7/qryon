//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REQWEST_BLOCKING_REQUEST_REQUESTBUILDER_MULTIPART_GEN_SOURCES: &[SourceDef] = &[];

static REQWEST_BLOCKING_REQUEST_REQUESTBUILDER_MULTIPART_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<reqwest::blocking::request::RequestBuilder>::multipart.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static REQWEST_BLOCKING_REQUEST_REQUESTBUILDER_MULTIPART_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REQWEST_BLOCKING_REQUEST_REQUESTBUILDER_MULTIPART_GEN_IMPORTS: &[&str] =
    &["<reqwest::blocking::request::RequestBuilder>::multipart"];

pub static REQWEST_BLOCKING_REQUEST_REQUESTBUILDER_MULTIPART_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<reqwest::blocking::request::requestbuilder>::multipart_generated",
        description: "Generated profile for <reqwest::blocking::request::RequestBuilder>::multipart from CodeQL/Pysa",
        detect_imports: REQWEST_BLOCKING_REQUEST_REQUESTBUILDER_MULTIPART_GEN_IMPORTS,
        sources: REQWEST_BLOCKING_REQUEST_REQUESTBUILDER_MULTIPART_GEN_SOURCES,
        sinks: REQWEST_BLOCKING_REQUEST_REQUESTBUILDER_MULTIPART_GEN_SINKS,
        sanitizers: REQWEST_BLOCKING_REQUEST_REQUESTBUILDER_MULTIPART_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
