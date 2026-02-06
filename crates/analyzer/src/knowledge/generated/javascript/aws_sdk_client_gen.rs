//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static AWS_SDK_CLIENT_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "@aws-sdk/client.Client.ReturnValue.Member[send].ReturnValue.Awaited",
    pattern: SourceKind::MemberAccess("send.Awaited"),
    taint_label: "user_input",
    description: "CodeQL source: ReturnValue.Member[send].ReturnValue.Awaited (kind: database-access-result)",
}];

static AWS_SDK_CLIENT_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "@aws-sdk/client.Client.ReturnValue.Member[send].Argument[0]",
    pattern: SinkKind::FunctionCall("send"),
    rule_id: "javascript/gen-sql-injection",
    severity: Severity::Critical,
    description: "CodeQL sink: ReturnValue.Member[send].Argument[0] (kind: sql-injection)",
    cwe: Some("CWE-89"),
}];

static AWS_SDK_CLIENT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static AWS_SDK_CLIENT_GEN_IMPORTS: &[&str] = &["@aws-sdk/client.Client"];

pub static AWS_SDK_CLIENT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "@aws_sdk_client_generated",
    description: "Generated profile for @aws-sdk/client.Client from CodeQL/Pysa",
    detect_imports: AWS_SDK_CLIENT_GEN_IMPORTS,
    sources: AWS_SDK_CLIENT_GEN_SOURCES,
    sinks: AWS_SDK_CLIENT_GEN_SINKS,
    sanitizers: AWS_SDK_CLIENT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
