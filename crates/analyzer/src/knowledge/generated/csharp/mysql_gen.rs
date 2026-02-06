//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MYSQL_GEN_SOURCES: &[SourceDef] = &[];

static MYSQL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.ExecuteDataRow",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.ExecuteDataRow"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.ExecuteDataRow (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.ExecuteDataRowAsync",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.ExecuteDataRowAsync"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.ExecuteDataRowAsync (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.ExecuteDataset",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.ExecuteDataset"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.ExecuteDataset (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.ExecuteDatasetAsync",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.ExecuteDatasetAsync"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.ExecuteDatasetAsync (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.ExecuteNonQuery",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.ExecuteNonQuery"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.ExecuteNonQuery (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.ExecuteNonQueryAsync",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.ExecuteNonQueryAsync"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.ExecuteNonQueryAsync (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.ExecuteReader",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.ExecuteReader"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.ExecuteReader (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.ExecuteReaderAsync",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.ExecuteReaderAsync"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.ExecuteReaderAsync (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.ExecuteScalar",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.ExecuteScalar"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.ExecuteScalar (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.ExecuteScalarAsync",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.ExecuteScalarAsync"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.ExecuteScalarAsync (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.UpdateDataset",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.UpdateDataset"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.UpdateDataset (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "MySql.Data.MySqlClient.MySqlHelper.UpdateDatasetAsync",
        pattern: SinkKind::FunctionCall("MySql.Data.MySqlClient.MySqlHelper.UpdateDatasetAsync"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: MySql.Data.MySqlClient.MySqlHelper.UpdateDatasetAsync (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static MYSQL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MYSQL_GEN_IMPORTS: &[&str] = &["MySql.Data.MySqlClient"];

pub static MYSQL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mysql_generated",
    description: "Generated profile for MySql.Data.MySqlClient from CodeQL/Pysa",
    detect_imports: MYSQL_GEN_IMPORTS,
    sources: MYSQL_GEN_SOURCES,
    sinks: MYSQL_GEN_SINKS,
    sanitizers: MYSQL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
