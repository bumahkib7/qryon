//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SAP_HANA_CLIENT_EXTENSION_STREAM_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "@sap/hana-client/extension/Stream.Member[createProcStatement].Argument[2].Parameter[1].Member[exec].Argument[1].Parameter[2..]",
    pattern: SourceKind::MemberAccess("createProcStatement.Parameter[1].exec.Parameter[2.]"),
    taint_label: "user_input",
    description: "CodeQL source: Member[createProcStatement].Argument[2].Parameter[1].Member[exec].Argument[1].Parameter[2..] (kind: database-access-result)",
}];

static SAP_HANA_CLIENT_EXTENSION_STREAM_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "@sap/hana-client/extension/Stream.Member[createProcStatement].Argument[1]",
    pattern: SinkKind::FunctionCall("createProcStatement"),
    rule_id: "javascript/gen-sql-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Member[createProcStatement].Argument[1] (kind: sql-injection)",
    cwe: Some("CWE-89"),
}];

static SAP_HANA_CLIENT_EXTENSION_STREAM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SAP_HANA_CLIENT_EXTENSION_STREAM_GEN_IMPORTS: &[&str] =
    &["@sap/hana-client/extension/Stream"];

pub static SAP_HANA_CLIENT_EXTENSION_STREAM_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "@sap_hana_client_extension_stream_generated",
    description: "Generated profile for @sap/hana-client/extension/Stream from CodeQL/Pysa",
    detect_imports: SAP_HANA_CLIENT_EXTENSION_STREAM_GEN_IMPORTS,
    sources: SAP_HANA_CLIENT_EXTENSION_STREAM_GEN_SOURCES,
    sinks: SAP_HANA_CLIENT_EXTENSION_STREAM_GEN_SINKS,
    sanitizers: SAP_HANA_CLIENT_EXTENSION_STREAM_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
