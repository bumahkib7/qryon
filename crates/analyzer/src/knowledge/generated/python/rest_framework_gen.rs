//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REST_FRAMEWORK_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "rest_framework.request.Request.POST",
        pattern: SourceKind::MemberAccess("rest_framework.request.Request.POST"),
        taint_label: "user_input",
        description: "Pysa source: rest_framework.request.Request.POST (kind: UserControlled)",
    },
    SourceDef {
        name: "rest_framework.request.Request.FILES",
        pattern: SourceKind::MemberAccess("rest_framework.request.Request.FILES"),
        taint_label: "user_input",
        description: "Pysa source: rest_framework.request.Request.FILES (kind: UserControlled)",
    },
    SourceDef {
        name: "rest_framework.request.Request.DATA",
        pattern: SourceKind::MemberAccess("rest_framework.request.Request.DATA"),
        taint_label: "user_input",
        description: "Pysa source: rest_framework.request.Request.DATA (kind: UserControlled)",
    },
    SourceDef {
        name: "rest_framework.request.Request.QUERY_PARAMS",
        pattern: SourceKind::MemberAccess("rest_framework.request.Request.QUERY_PARAMS"),
        taint_label: "user_input",
        description: "Pysa source: rest_framework.request.Request.QUERY_PARAMS (kind: UserControlled)",
    },
    SourceDef {
        name: "rest_framework.request.Request.data",
        pattern: SourceKind::MemberAccess("rest_framework.request.Request.data"),
        taint_label: "user_input",
        description: "Pysa source: rest_framework.request.Request.data (kind: UserControlled)",
    },
    SourceDef {
        name: "rest_framework.request.Request.query_params",
        pattern: SourceKind::MemberAccess("rest_framework.request.Request.query_params"),
        taint_label: "user_input",
        description: "Pysa source: rest_framework.request.Request.query_params (kind: UserControlled)",
    },
    SourceDef {
        name: "rest_framework.request.Request.content_type",
        pattern: SourceKind::MemberAccess("rest_framework.request.Request.content_type"),
        taint_label: "user_input",
        description: "Pysa source: rest_framework.request.Request.content_type (kind: UserControlled)",
    },
    SourceDef {
        name: "rest_framework.request.Request.stream",
        pattern: SourceKind::MemberAccess("rest_framework.request.Request.stream"),
        taint_label: "user_input",
        description: "Pysa source: rest_framework.request.Request.stream (kind: UserControlled)",
    },
];

static REST_FRAMEWORK_GEN_SINKS: &[SinkDef] = &[];

static REST_FRAMEWORK_GEN_SANITIZERS: &[SanitizerDef] = &[];

static REST_FRAMEWORK_GEN_IMPORTS: &[&str] = &["rest_framework"];

pub static REST_FRAMEWORK_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "rest_framework_generated",
    description: "Generated profile for rest_framework from CodeQL/Pysa",
    detect_imports: REST_FRAMEWORK_GEN_IMPORTS,
    sources: REST_FRAMEWORK_GEN_SOURCES,
    sinks: REST_FRAMEWORK_GEN_SINKS,
    sanitizers: REST_FRAMEWORK_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
