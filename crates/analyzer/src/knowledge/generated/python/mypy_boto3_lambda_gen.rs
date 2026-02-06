//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MYPY_BOTO3_LAMBDA_GEN_SOURCES: &[SourceDef] = &[];

static MYPY_BOTO3_LAMBDA_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "mypy_boto3_lambda.client.LambdaClient.create_function",
        pattern: SinkKind::FunctionCall("mypy_boto3_lambda.client.LambdaClient.create_function"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: mypy_boto3_lambda.client.LambdaClient.create_function (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "mypy_boto3_lambda.client.LambdaClient.update_function_code",
        pattern: SinkKind::FunctionCall(
            "mypy_boto3_lambda.client.LambdaClient.update_function_code",
        ),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: mypy_boto3_lambda.client.LambdaClient.update_function_code (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
];

static MYPY_BOTO3_LAMBDA_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MYPY_BOTO3_LAMBDA_GEN_IMPORTS: &[&str] = &["mypy_boto3_lambda"];

pub static MYPY_BOTO3_LAMBDA_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mypy_boto3_lambda_generated",
    description: "Generated profile for mypy_boto3_lambda from CodeQL/Pysa",
    detect_imports: MYPY_BOTO3_LAMBDA_GEN_IMPORTS,
    sources: MYPY_BOTO3_LAMBDA_GEN_SOURCES,
    sinks: MYPY_BOTO3_LAMBDA_GEN_SINKS,
    sanitizers: MYPY_BOTO3_LAMBDA_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
