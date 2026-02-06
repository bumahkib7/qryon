//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HDB_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "hdb.Client.Member[exec,execute].Argument[1..2].Parameter[1]",
        pattern: SourceKind::MemberAccess("exec,execute.Argument[1.2].Parameter[1]"),
        taint_label: "user_input",
        description: "CodeQL source: Member[exec,execute].Argument[1..2].Parameter[1] (kind: database-access-result)",
    },
    SourceDef {
        name: "hdb.Client.Member[prepare].Argument[1].Parameter[1].Member[exec].Argument[1].Parameter[2..]",
        pattern: SourceKind::MemberAccess("prepare.Parameter[1].exec.Parameter[2.]"),
        taint_label: "user_input",
        description: "CodeQL source: Member[prepare].Argument[1].Parameter[1].Member[exec].Argument[1].Parameter[2..] (kind: database-access-result)",
    },
];

static HDB_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "hdb.Client.Member[exec,prepare,execute].Argument[0]",
    pattern: SinkKind::FunctionCall("exec,prepare,execute"),
    rule_id: "javascript/gen-sql-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: Member[exec,prepare,execute].Argument[0] (kind: sql-injection)",
    cwe: Some("CWE-89"),
}];

static HDB_GEN_SANITIZERS: &[SanitizerDef] = &[];

static HDB_GEN_IMPORTS: &[&str] = &["hdb.Client"];

pub static HDB_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "hdb_generated",
    description: "Generated profile for hdb.Client from CodeQL/Pysa",
    detect_imports: HDB_GEN_IMPORTS,
    sources: HDB_GEN_SOURCES,
    sinks: HDB_GEN_SINKS,
    sanitizers: HDB_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
