//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MYPY_BOTO3_APPLICATION_INSIGHTS_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "mypy_boto3_application_insights.client.ApplicationInsightsClient.list_configuration_history",
        pattern: SourceKind::MemberAccess(
            "mypy_boto3_application_insights.client.ApplicationInsightsClient.list_configuration_history",
        ),
        taint_label: "user_input",
        description: "Pysa source: mypy_boto3_application_insights.client.ApplicationInsightsClient.list_configuration_history (kind: ExceptionMessage)",
    },
    SourceDef {
        name: "mypy_boto3_application_insights.client.ApplicationInsightsClient.list_log_pattern_sets",
        pattern: SourceKind::MemberAccess(
            "mypy_boto3_application_insights.client.ApplicationInsightsClient.list_log_pattern_sets",
        ),
        taint_label: "user_input",
        description: "Pysa source: mypy_boto3_application_insights.client.ApplicationInsightsClient.list_log_pattern_sets (kind: ExceptionMessage)",
    },
    SourceDef {
        name: "mypy_boto3_application_insights.client.ApplicationInsightsClient.list_log_patterns",
        pattern: SourceKind::MemberAccess(
            "mypy_boto3_application_insights.client.ApplicationInsightsClient.list_log_patterns",
        ),
        taint_label: "user_input",
        description: "Pysa source: mypy_boto3_application_insights.client.ApplicationInsightsClient.list_log_patterns (kind: ExceptionMessage)",
    },
    SourceDef {
        name: "mypy_boto3_application_insights.client.ApplicationInsightsClient.list_problems",
        pattern: SourceKind::MemberAccess(
            "mypy_boto3_application_insights.client.ApplicationInsightsClient.list_problems",
        ),
        taint_label: "user_input",
        description: "Pysa source: mypy_boto3_application_insights.client.ApplicationInsightsClient.list_problems (kind: ExceptionMessage)",
    },
];

static MYPY_BOTO3_APPLICATION_INSIGHTS_GEN_SINKS: &[SinkDef] = &[];

static MYPY_BOTO3_APPLICATION_INSIGHTS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MYPY_BOTO3_APPLICATION_INSIGHTS_GEN_IMPORTS: &[&str] = &["mypy_boto3_application_insights"];

pub static MYPY_BOTO3_APPLICATION_INSIGHTS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mypy_boto3_application_insights_generated",
    description: "Generated profile for mypy_boto3_application_insights from CodeQL/Pysa",
    detect_imports: MYPY_BOTO3_APPLICATION_INSIGHTS_GEN_IMPORTS,
    sources: MYPY_BOTO3_APPLICATION_INSIGHTS_GEN_SOURCES,
    sinks: MYPY_BOTO3_APPLICATION_INSIGHTS_GEN_SINKS,
    sanitizers: MYPY_BOTO3_APPLICATION_INSIGHTS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
