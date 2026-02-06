//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MYPY_BOTO3_APIGATEWAY_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "mypy_boto3_apigateway.client.APIGatewayClient.create_api_key",
        pattern: SourceKind::MemberAccess(
            "mypy_boto3_apigateway.client.APIGatewayClient.create_api_key",
        ),
        taint_label: "user_input",
        description: "Pysa source: mypy_boto3_apigateway.client.APIGatewayClient.create_api_key (kind: ServerSecrets)",
    },
    SourceDef {
        name: "mypy_boto3_apigateway.client.APIGatewayClient.get_api_key",
        pattern: SourceKind::MemberAccess(
            "mypy_boto3_apigateway.client.APIGatewayClient.get_api_key",
        ),
        taint_label: "user_input",
        description: "Pysa source: mypy_boto3_apigateway.client.APIGatewayClient.get_api_key (kind: ServerSecrets)",
    },
    SourceDef {
        name: "mypy_boto3_apigateway.client.APIGatewayClient.get_api_keys",
        pattern: SourceKind::MemberAccess(
            "mypy_boto3_apigateway.client.APIGatewayClient.get_api_keys",
        ),
        taint_label: "user_input",
        description: "Pysa source: mypy_boto3_apigateway.client.APIGatewayClient.get_api_keys (kind: ServerSecrets)",
    },
    SourceDef {
        name: "mypy_boto3_apigateway.client.APIGatewayClient.get_authorizer",
        pattern: SourceKind::MemberAccess(
            "mypy_boto3_apigateway.client.APIGatewayClient.get_authorizer",
        ),
        taint_label: "user_input",
        description: "Pysa source: mypy_boto3_apigateway.client.APIGatewayClient.get_authorizer (kind: ServerSecrets)",
    },
    SourceDef {
        name: "mypy_boto3_apigateway.client.APIGatewayClient.get_client_certificate",
        pattern: SourceKind::MemberAccess(
            "mypy_boto3_apigateway.client.APIGatewayClient.get_client_certificate",
        ),
        taint_label: "user_input",
        description: "Pysa source: mypy_boto3_apigateway.client.APIGatewayClient.get_client_certificate (kind: ServerSecrets)",
    },
    SourceDef {
        name: "mypy_boto3_apigateway.client.APIGatewayClient.get_client_certificates",
        pattern: SourceKind::MemberAccess(
            "mypy_boto3_apigateway.client.APIGatewayClient.get_client_certificates",
        ),
        taint_label: "user_input",
        description: "Pysa source: mypy_boto3_apigateway.client.APIGatewayClient.get_client_certificates (kind: ServerSecrets)",
    },
];

static MYPY_BOTO3_APIGATEWAY_GEN_SINKS: &[SinkDef] = &[];

static MYPY_BOTO3_APIGATEWAY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MYPY_BOTO3_APIGATEWAY_GEN_IMPORTS: &[&str] = &["mypy_boto3_apigateway"];

pub static MYPY_BOTO3_APIGATEWAY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mypy_boto3_apigateway_generated",
    description: "Generated profile for mypy_boto3_apigateway from CodeQL/Pysa",
    detect_imports: MYPY_BOTO3_APIGATEWAY_GEN_IMPORTS,
    sources: MYPY_BOTO3_APIGATEWAY_GEN_SOURCES,
    sinks: MYPY_BOTO3_APIGATEWAY_GEN_SINKS,
    sanitizers: MYPY_BOTO3_APIGATEWAY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
