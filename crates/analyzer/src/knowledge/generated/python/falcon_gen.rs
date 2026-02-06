//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FALCON_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "falcon.response.Response._media",
        pattern: SourceKind::MemberAccess("falcon.response.Response._media"),
        taint_label: "user_input",
        description: "Pysa source: falcon.response.Response._media (kind: ResponseData)",
    },
    SourceDef {
        name: "falcon.response.Response.body",
        pattern: SourceKind::MemberAccess("falcon.response.Response.body"),
        taint_label: "user_input",
        description: "Pysa source: falcon.response.Response.body (kind: ResponseData)",
    },
    SourceDef {
        name: "falcon.response.Response._data",
        pattern: SourceKind::MemberAccess("falcon.response.Response._data"),
        taint_label: "user_input",
        description: "Pysa source: falcon.response.Response._data (kind: ResponseData)",
    },
    SourceDef {
        name: "falcon.response.Response.stream",
        pattern: SourceKind::MemberAccess("falcon.response.Response.stream"),
        taint_label: "user_input",
        description: "Pysa source: falcon.response.Response.stream (kind: ResponseData)",
    },
];

static FALCON_GEN_SINKS: &[SinkDef] = &[];

static FALCON_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FALCON_GEN_IMPORTS: &[&str] = &["falcon"];

pub static FALCON_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "falcon_generated",
    description: "Generated profile for falcon from CodeQL/Pysa",
    detect_imports: FALCON_GEN_IMPORTS,
    sources: FALCON_GEN_SOURCES,
    sinks: FALCON_GEN_SINKS,
    sanitizers: FALCON_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
