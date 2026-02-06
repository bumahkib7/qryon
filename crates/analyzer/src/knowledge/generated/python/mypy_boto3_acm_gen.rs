//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MYPY_BOTO3_ACM_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "mypy_boto3_acm.client.ACMClient.export_certificate",
    pattern: SourceKind::MemberAccess("mypy_boto3_acm.client.ACMClient.export_certificate"),
    taint_label: "user_input",
    description: "Pysa source: mypy_boto3_acm.client.ACMClient.export_certificate (kind: ServerSecrets)",
}];

static MYPY_BOTO3_ACM_GEN_SINKS: &[SinkDef] = &[];

static MYPY_BOTO3_ACM_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MYPY_BOTO3_ACM_GEN_IMPORTS: &[&str] = &["mypy_boto3_acm"];

pub static MYPY_BOTO3_ACM_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mypy_boto3_acm_generated",
    description: "Generated profile for mypy_boto3_acm from CodeQL/Pysa",
    detect_imports: MYPY_BOTO3_ACM_GEN_IMPORTS,
    sources: MYPY_BOTO3_ACM_GEN_SOURCES,
    sinks: MYPY_BOTO3_ACM_GEN_SINKS,
    sanitizers: MYPY_BOTO3_ACM_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
