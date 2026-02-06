//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AMAZON_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Headers",
        pattern: SourceKind::MemberAccess(
            "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Headers",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Headers (kind: manual)",
    },
    SourceDef {
        name: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Body",
        pattern: SourceKind::MemberAccess(
            "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Body",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Body (kind: manual)",
    },
    SourceDef {
        name: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_RawPath",
        pattern: SourceKind::MemberAccess(
            "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_RawPath",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_RawPath (kind: manual)",
    },
    SourceDef {
        name: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_RawQueryString",
        pattern: SourceKind::MemberAccess(
            "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_RawQueryString",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_RawQueryString (kind: manual)",
    },
    SourceDef {
        name: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Cookies",
        pattern: SourceKind::MemberAccess(
            "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Cookies",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Cookies (kind: manual)",
    },
    SourceDef {
        name: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_PathParameters",
        pattern: SourceKind::MemberAccess(
            "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_PathParameters",
        ),
        taint_label: "user_input",
        description: "CodeQL source: Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_PathParameters (kind: manual)",
    },
];

static AMAZON_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "Amazon.Lambda.Core.ILambdaLogger.Log",
        pattern: SinkKind::FunctionCall("Amazon.Lambda.Core.ILambdaLogger.Log"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Amazon.Lambda.Core.ILambdaLogger.Log (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Amazon.Lambda.Core.ILambdaLogger.LogLine",
        pattern: SinkKind::FunctionCall("Amazon.Lambda.Core.ILambdaLogger.LogLine"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Amazon.Lambda.Core.ILambdaLogger.LogLine (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Amazon.Lambda.Core.ILambdaLogger.LogTrace",
        pattern: SinkKind::FunctionCall("Amazon.Lambda.Core.ILambdaLogger.LogTrace"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Amazon.Lambda.Core.ILambdaLogger.LogTrace (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Amazon.Lambda.Core.ILambdaLogger.LogDebug",
        pattern: SinkKind::FunctionCall("Amazon.Lambda.Core.ILambdaLogger.LogDebug"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Amazon.Lambda.Core.ILambdaLogger.LogDebug (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Amazon.Lambda.Core.ILambdaLogger.LogInformation",
        pattern: SinkKind::FunctionCall("Amazon.Lambda.Core.ILambdaLogger.LogInformation"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Amazon.Lambda.Core.ILambdaLogger.LogInformation (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Amazon.Lambda.Core.ILambdaLogger.LogWarning",
        pattern: SinkKind::FunctionCall("Amazon.Lambda.Core.ILambdaLogger.LogWarning"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Amazon.Lambda.Core.ILambdaLogger.LogWarning (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Amazon.Lambda.Core.ILambdaLogger.LogError",
        pattern: SinkKind::FunctionCall("Amazon.Lambda.Core.ILambdaLogger.LogError"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Amazon.Lambda.Core.ILambdaLogger.LogError (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "Amazon.Lambda.Core.ILambdaLogger.LogCritical",
        pattern: SinkKind::FunctionCall("Amazon.Lambda.Core.ILambdaLogger.LogCritical"),
        rule_id: "csharp/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: Amazon.Lambda.Core.ILambdaLogger.LogCritical (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static AMAZON_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AMAZON_GEN_IMPORTS: &[&str] = &["Amazon.Lambda.APIGatewayEvents", "Amazon.Lambda.Core"];

pub static AMAZON_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "amazon_generated",
    description: "Generated profile for Amazon.Lambda.APIGatewayEvents from CodeQL/Pysa",
    detect_imports: AMAZON_GEN_IMPORTS,
    sources: AMAZON_GEN_SOURCES,
    sinks: AMAZON_GEN_SINKS,
    sanitizers: AMAZON_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
