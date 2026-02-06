//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MYPY_BOTO3_RDS_DATA_GEN_SOURCES: &[SourceDef] = &[];

static MYPY_BOTO3_RDS_DATA_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "mypy_boto3_rds_data.client.RDSDataServiceClient.batch_execute_statement",
        pattern: SinkKind::FunctionCall(
            "mypy_boto3_rds_data.client.RDSDataServiceClient.batch_execute_statement",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mypy_boto3_rds_data.client.RDSDataServiceClient.batch_execute_statement (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mypy_boto3_rds_data.client.RDSDataServiceClient.execute_sql",
        pattern: SinkKind::FunctionCall(
            "mypy_boto3_rds_data.client.RDSDataServiceClient.execute_sql",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mypy_boto3_rds_data.client.RDSDataServiceClient.execute_sql (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "mypy_boto3_rds_data.client.RDSDataServiceClient.execute_statement",
        pattern: SinkKind::FunctionCall(
            "mypy_boto3_rds_data.client.RDSDataServiceClient.execute_statement",
        ),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: mypy_boto3_rds_data.client.RDSDataServiceClient.execute_statement (kind: SQL)",
        cwe: Some("CWE-89"),
    },
];

static MYPY_BOTO3_RDS_DATA_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MYPY_BOTO3_RDS_DATA_GEN_IMPORTS: &[&str] = &["mypy_boto3_rds_data"];

pub static MYPY_BOTO3_RDS_DATA_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mypy_boto3_rds_data_generated",
    description: "Generated profile for mypy_boto3_rds_data from CodeQL/Pysa",
    detect_imports: MYPY_BOTO3_RDS_DATA_GEN_IMPORTS,
    sources: MYPY_BOTO3_RDS_DATA_GEN_SOURCES,
    sinks: MYPY_BOTO3_RDS_DATA_GEN_SINKS,
    sanitizers: MYPY_BOTO3_RDS_DATA_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
