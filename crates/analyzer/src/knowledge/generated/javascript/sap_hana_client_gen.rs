//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SAP_HANA_CLIENT_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "@sap/hana-client.Member[createConnection].ReturnValue.Member[exec].Argument[1].Parameter[1]",
        pattern: SourceKind::MemberAccess("createConnection.exec.Parameter[1]"),
        taint_label: "user_input",
        description: "CodeQL source: Member[createConnection].ReturnValue.Member[exec].Argument[1].Parameter[1] (kind: database-access-result)",
    },
    SourceDef {
        name: "@sap/hana-client.Member[createConnection].ReturnValue.Member[prepare].ReturnValue.Member[execBatch,exec,execQuery].Argument[1].Parameter[1]",
        pattern: SourceKind::MemberAccess(
            "createConnection.prepare.execBatch,exec,execQuery.Parameter[1]",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Member[createConnection].ReturnValue.Member[prepare].ReturnValue.Member[execBatch,exec,execQuery].Argument[1].Parameter[1] (kind: database-access-result)",
    },
];

static SAP_HANA_CLIENT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "@sap/hana-client.Member[createConnection].ReturnValue.Member[exec,prepare].Argument[0]",
    pattern: SinkKind::FunctionCall("createConnection.exec,prepare"),
    rule_id: "javascript/gen-sql-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Member[createConnection].ReturnValue.Member[exec,prepare].Argument[0] (kind: sql-injection)",
    cwe: Some("CWE-89"),
}];

static SAP_HANA_CLIENT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static SAP_HANA_CLIENT_GEN_IMPORTS: &[&str] = &["@sap/hana-client"];

pub static SAP_HANA_CLIENT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "@sap_hana_client_generated",
    description: "Generated profile for @sap/hana-client from CodeQL/Pysa",
    detect_imports: SAP_HANA_CLIENT_GEN_IMPORTS,
    sources: SAP_HANA_CLIENT_GEN_SOURCES,
    sinks: SAP_HANA_CLIENT_GEN_SINKS,
    sanitizers: SAP_HANA_CLIENT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
