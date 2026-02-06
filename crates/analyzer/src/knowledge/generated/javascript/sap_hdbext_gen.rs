//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SAP_HDBEXT_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "@sap/hdbext.Member[loadProcedure].Argument[3].Parameter[1].Argument[2].Parameter[2..]",
    pattern: SourceKind::MemberAccess("loadProcedure.Parameter[1].Parameter[2.]"),
    taint_label: "user_input",
    description: "CodeQL source: Member[loadProcedure].Argument[3].Parameter[1].Argument[2].Parameter[2..] (kind: database-access-result)",
}];

static SAP_HDBEXT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "@sap/hdbext.Member[loadProcedure].Argument[2]",
    pattern: SinkKind::FunctionCall("loadProcedure"),
    rule_id: "javascript/gen-sql-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Member[loadProcedure].Argument[2] (kind: sql-injection)",
    cwe: Some("CWE-89"),
}];

static SAP_HDBEXT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SAP_HDBEXT_GEN_IMPORTS: &[&str] = &["@sap/hdbext"];

pub static SAP_HDBEXT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "@sap_hdbext_generated",
    description: "Generated profile for @sap/hdbext from CodeQL/Pysa",
    detect_imports: SAP_HDBEXT_GEN_IMPORTS,
    sources: SAP_HDBEXT_GEN_SOURCES,
    sinks: SAP_HDBEXT_GEN_SINKS,
    sanitizers: SAP_HDBEXT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
