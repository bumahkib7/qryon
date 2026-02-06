//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PLAY_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "play.mvc.Http$Request.body",
        pattern: SourceKind::MemberAccess("play.mvc.Http$Request.body"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$Request.body (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.cookie",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.cookie"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.cookie (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.cookies",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.cookies"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.cookies (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.getHeader",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.getHeader"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.getHeader (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.getHeaders",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.getHeaders"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.getHeaders (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.getQueryString",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.getQueryString"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.getQueryString (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.header",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.header"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.header (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.headers",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.headers"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.headers (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.host",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.host"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.host (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.path",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.path"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.path (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.queryString",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.queryString"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.queryString (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.remoteAddress",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.remoteAddress"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.remoteAddress (kind: manual)",
    },
    SourceDef {
        name: "play.mvc.Http$RequestHeader.uri",
        pattern: SourceKind::MemberAccess("play.mvc.Http$RequestHeader.uri"),
        taint_label: "user_input",
        description: "CodeQL source: play.mvc.Http$RequestHeader.uri (kind: manual)",
    },
];

static PLAY_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "play.libs.ws.WSClient.url",
        pattern: SinkKind::FunctionCall("play.libs.ws.WSClient.url"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: play.libs.ws.WSClient.url (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "play.libs.ws.StandaloneWSClient.url",
        pattern: SinkKind::FunctionCall("play.libs.ws.StandaloneWSClient.url"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: play.libs.ws.StandaloneWSClient.url (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "play.mvc.Result.addingToSession",
        pattern: SinkKind::FunctionCall("play.mvc.Result.addingToSession"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: play.mvc.Result.addingToSession (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static PLAY_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "play.mvc.Http$RequestBody.asFormUrlEncoded",
        pattern: SanitizerKind::Function("play.mvc.Http$RequestBody.asFormUrlEncoded"),
        sanitizes: "url",
        description: "CodeQL sanitizer: play.mvc.Http$RequestBody.asFormUrlEncoded",
    },
    SanitizerDef {
        name: "play.mvc.Http$MultipartFormData.asFormUrlEncoded",
        pattern: SanitizerKind::Function("play.mvc.Http$MultipartFormData.asFormUrlEncoded"),
        sanitizes: "url",
        description: "CodeQL sanitizer: play.mvc.Http$MultipartFormData.asFormUrlEncoded",
    },
];

static PLAY_GEN_IMPORTS: &[&str] = &["play.libs.ws", "play.mvc"];

pub static PLAY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "play_generated",
    description: "Generated profile for play.libs.ws from CodeQL/Pysa",
    detect_imports: PLAY_GEN_IMPORTS,
    sources: PLAY_GEN_SOURCES,
    sinks: PLAY_GEN_SINKS,
    sanitizers: PLAY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
