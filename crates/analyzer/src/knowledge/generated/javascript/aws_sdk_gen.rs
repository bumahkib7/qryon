//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AWS_SDK_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "aws-sdk.Athena.ReturnValue.Member[getQueryResults].ReturnValue.Member[promise].ReturnValue.Awaited",
        pattern: SourceKind::MemberAccess("getQueryResults.promise.Awaited"),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue.Member[getQueryResults].ReturnValue.Member[promise].ReturnValue.Awaited (kind: database-access-result)",
    },
    SourceDef {
        name: "aws-sdk.Athena.ReturnValue.Member[getQueryResults].Argument[1].Parameter[1]",
        pattern: SourceKind::MemberAccess("getQueryResults.Parameter[1]"),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue.Member[getQueryResults].Argument[1].Parameter[1] (kind: database-access-result)",
    },
    SourceDef {
        name: "aws-sdk.S3.ReturnValue.Member[getObject].ReturnValue.Member[promise].ReturnValue.Awaited",
        pattern: SourceKind::MemberAccess("getObject.promise.Awaited"),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue.Member[getObject].ReturnValue.Member[promise].ReturnValue.Awaited (kind: database-access-result)",
    },
    SourceDef {
        name: "aws-sdk.S3.ReturnValue.Member[getObject].Argument[1].Parameter[1]",
        pattern: SourceKind::MemberAccess("getObject.Parameter[1]"),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue.Member[getObject].Argument[1].Parameter[1] (kind: database-access-result)",
    },
    SourceDef {
        name: "aws-sdk.RDSDataService.ReturnValue.Member[executeStatement,batchExecuteStatement].ReturnValue.Member[promise].ReturnValue.Awaited",
        pattern: SourceKind::MemberAccess("executeStatement,batchExecuteStatement.promise.Awaited"),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue.Member[executeStatement,batchExecuteStatement].ReturnValue.Member[promise].ReturnValue.Awaited (kind: database-access-result)",
    },
    SourceDef {
        name: "aws-sdk.RDSDataService.ReturnValue.Member[executeStatement,batchExecuteStatement].Argument[1].Parameter[1]",
        pattern: SourceKind::MemberAccess("executeStatement,batchExecuteStatement.Parameter[1]"),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue.Member[executeStatement,batchExecuteStatement].Argument[1].Parameter[1] (kind: database-access-result)",
    },
    SourceDef {
        name: "aws-sdk.DynamoDB.ReturnValue.Member[executeStatement,batchExecuteStatement,query,scan,getItem,batchGetItem].ReturnValue.Member[promise].ReturnValue.Awaited",
        pattern: SourceKind::MemberAccess(
            "executeStatement,batchExecuteStatement,query,scan,getItem,batchGetItem.promise.Awaited",
        ),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue.Member[executeStatement,batchExecuteStatement,query,scan,getItem,batchGetItem].ReturnValue.Member[promise].ReturnValue.Awaited (kind: database-access-result)",
    },
    SourceDef {
        name: "aws-sdk.DynamoDB.ReturnValue.Member[executeStatement,batchExecuteStatement,query,scan,getItem,batchGetItem].Argument[1].Parameter[1]",
        pattern: SourceKind::MemberAccess(
            "executeStatement,batchExecuteStatement,query,scan,getItem,batchGetItem.Parameter[1]",
        ),
        taint_label: "user_input",
        description: "CodeQL source: ReturnValue.Member[executeStatement,batchExecuteStatement,query,scan,getItem,batchGetItem].Argument[1].Parameter[1] (kind: database-access-result)",
    },
];

static AWS_SDK_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "aws-sdk.AnyMember.Argument[0].Member[secretAccessKey,accessKeyId]",
        pattern: SinkKind::FunctionCall("AnyMember.secretAccessKey,accessKeyId"),
        rule_id: "javascript/gen-credentials-key",
        severity: Severity::Error,
        description: "CodeQL sink: AnyMember.Argument[0].Member[secretAccessKey,accessKeyId] (kind: credentials-key)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "aws-sdk.AnyMember.Member[secretAccessKey,accessKeyId]",
        pattern: SinkKind::FunctionCall("AnyMember.secretAccessKey,accessKeyId"),
        rule_id: "javascript/gen-credentials-key",
        severity: Severity::Error,
        description: "CodeQL sink: AnyMember.Member[secretAccessKey,accessKeyId] (kind: credentials-key)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "aws-sdk.Member[Credentials].Argument[0,1]",
        pattern: SinkKind::FunctionCall("Credentials.Argument[0,1]"),
        rule_id: "javascript/gen-credentials-key",
        severity: Severity::Error,
        description: "CodeQL sink: Member[Credentials].Argument[0,1] (kind: credentials-key)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "aws-sdk.Athena.ReturnValue.Member[startQueryExecution,createNamedQuery,updateNamedQuery].Argument[0].Member[QueryString]",
        pattern: SinkKind::FunctionCall(
            "startQueryExecution,createNamedQuery,updateNamedQuery.QueryString",
        ),
        rule_id: "javascript/gen-sql-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: ReturnValue.Member[startQueryExecution,createNamedQuery,updateNamedQuery].Argument[0].Member[QueryString] (kind: sql-injection)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "aws-sdk.S3.ReturnValue.Member[selectObjectContent].Argument[0].Member[Expression]",
        pattern: SinkKind::FunctionCall("selectObjectContent.Expression"),
        rule_id: "javascript/gen-sql-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: ReturnValue.Member[selectObjectContent].Argument[0].Member[Expression] (kind: sql-injection)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "aws-sdk.RDSDataService.ReturnValue.Member[executeStatement,batchExecuteStatement].Argument[0].Member[sql]",
        pattern: SinkKind::FunctionCall("executeStatement,batchExecuteStatement.sql"),
        rule_id: "javascript/gen-sql-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: ReturnValue.Member[executeStatement,batchExecuteStatement].Argument[0].Member[sql] (kind: sql-injection)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "aws-sdk.RDSDataService.ReturnValue.Member[batchExecuteStatement].Argument[0].Member[parameterSets].ArrayElement.Member[sql]",
        pattern: SinkKind::FunctionCall("batchExecuteStatement.parameterSets.ArrayElement.sql"),
        rule_id: "javascript/gen-sql-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: ReturnValue.Member[batchExecuteStatement].Argument[0].Member[parameterSets].ArrayElement.Member[sql] (kind: sql-injection)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "aws-sdk.DynamoDB.ReturnValue.Member[executeStatement].Argument[0].Member[Statement]",
        pattern: SinkKind::FunctionCall("executeStatement.Statement"),
        rule_id: "javascript/gen-sql-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: ReturnValue.Member[executeStatement].Argument[0].Member[Statement] (kind: sql-injection)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "aws-sdk.DynamoDB.ReturnValue.Member[batchExecuteStatement].Argument[0].Member[Statements].ArrayElement.Member[Statement]",
        pattern: SinkKind::FunctionCall("batchExecuteStatement.Statements.ArrayElement.Statement"),
        rule_id: "javascript/gen-sql-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: ReturnValue.Member[batchExecuteStatement].Argument[0].Member[Statements].ArrayElement.Member[Statement] (kind: sql-injection)",
        cwe: Some("CWE-89"),
    },
];

static AWS_SDK_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AWS_SDK_GEN_IMPORTS: &[&str] = &[
    "aws-sdk.Athena",
    "aws-sdk.S3",
    "aws-sdk.RDSDataService",
    "aws-sdk.DynamoDB",
    "aws-sdk",
];

pub static AWS_SDK_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "aws_sdk_generated",
    description: "Generated profile for aws-sdk.Athena from CodeQL/Pysa",
    detect_imports: AWS_SDK_GEN_IMPORTS,
    sources: AWS_SDK_GEN_SOURCES,
    sinks: AWS_SDK_GEN_SINKS,
    sanitizers: AWS_SDK_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
