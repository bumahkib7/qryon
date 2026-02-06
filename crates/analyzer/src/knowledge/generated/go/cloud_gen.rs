//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static CLOUD_GEN_SOURCES: &[SourceDef] = &[];

static CLOUD_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "cloud.google.com/go/bigquery.Client.Query",
    pattern: SinkKind::FunctionCall("cloud.google.com/go/bigquery.Client.Query"),
    rule_id: "go/gen-manual",
    severity: Severity::Error,
    description: "CodeQL sink: cloud.google.com/go/bigquery.Client.Query (kind: manual)",
    cwe: Some("CWE-74"),
}];

static CLOUD_GEN_SANITIZERS: &[SanitizerDef] = &[];

static CLOUD_GEN_IMPORTS: &[&str] = &["cloud.google.com/go/bigquery"];

pub static CLOUD_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "cloud_generated",
    description: "Generated profile for cloud.google.com/go/bigquery from CodeQL/Pysa",
    detect_imports: CLOUD_GEN_IMPORTS,
    sources: CLOUD_GEN_SOURCES,
    sinks: CLOUD_GEN_SINKS,
    sanitizers: CLOUD_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
