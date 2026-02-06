//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ACTIX_HTTP_ONCONNECTDATA_FROM_IO_GEN_SOURCES: &[SourceDef] = &[];

static ACTIX_HTTP_ONCONNECTDATA_FROM_IO_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<actix_http::OnConnectData>::from_io.Argument[1]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-alloc-layout",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[1] (kind: alloc-layout)",
    cwe: Some("CWE-74"),
}];

static ACTIX_HTTP_ONCONNECTDATA_FROM_IO_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ACTIX_HTTP_ONCONNECTDATA_FROM_IO_GEN_IMPORTS: &[&str] =
    &["<actix_http::OnConnectData>::from_io"];

pub static ACTIX_HTTP_ONCONNECTDATA_FROM_IO_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "<actix_http::onconnectdata>::from_io_generated",
    description: "Generated profile for <actix_http::OnConnectData>::from_io from CodeQL/Pysa",
    detect_imports: ACTIX_HTTP_ONCONNECTDATA_FROM_IO_GEN_IMPORTS,
    sources: ACTIX_HTTP_ONCONNECTDATA_FROM_IO_GEN_SOURCES,
    sinks: ACTIX_HTTP_ONCONNECTDATA_FROM_IO_GEN_SINKS,
    sanitizers: ACTIX_HTTP_ONCONNECTDATA_FROM_IO_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
