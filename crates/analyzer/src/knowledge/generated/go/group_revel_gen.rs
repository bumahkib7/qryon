//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_REVEL_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "group:revel.Controller.Params",
        pattern: SourceKind::MemberAccess("group:revel.Controller.Params"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Controller.Params (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.Header",
        pattern: SourceKind::MemberAccess("group:revel.Request.Header"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.Header (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.ContentType",
        pattern: SourceKind::MemberAccess("group:revel.Request.ContentType"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.ContentType (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.AcceptLanguages",
        pattern: SourceKind::MemberAccess("group:revel.Request.AcceptLanguages"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.AcceptLanguages (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.Locale",
        pattern: SourceKind::MemberAccess("group:revel.Request.Locale"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.Locale (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.URL",
        pattern: SourceKind::MemberAccess("group:revel.Request.URL"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.URL (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.Form",
        pattern: SourceKind::MemberAccess("group:revel.Request.Form"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.Form (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.MultipartForm",
        pattern: SourceKind::MemberAccess("group:revel.Request.MultipartForm"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.MultipartForm (kind: manual)",
    },
    SourceDef {
        name: "group:revel.RouteMatch.Params",
        pattern: SourceKind::MemberAccess("group:revel.RouteMatch.Params"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.RouteMatch.Params (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.Cookie",
        pattern: SourceKind::MemberAccess("group:revel.Request.Cookie"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.Cookie (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.FormValue",
        pattern: SourceKind::MemberAccess("group:revel.Request.FormValue"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.FormValue (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.GetBody",
        pattern: SourceKind::MemberAccess("group:revel.Request.GetBody"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.GetBody (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.GetForm",
        pattern: SourceKind::MemberAccess("group:revel.Request.GetForm"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.GetForm (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.GetHttpHeader",
        pattern: SourceKind::MemberAccess("group:revel.Request.GetHttpHeader"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.GetHttpHeader (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.GetMultipartForm",
        pattern: SourceKind::MemberAccess("group:revel.Request.GetMultipartForm"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.GetMultipartForm (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.GetQuery",
        pattern: SourceKind::MemberAccess("group:revel.Request.GetQuery"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.GetQuery (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.GetRequestURI",
        pattern: SourceKind::MemberAccess("group:revel.Request.GetRequestURI"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.GetRequestURI (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.MultipartReader",
        pattern: SourceKind::MemberAccess("group:revel.Request.MultipartReader"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.MultipartReader (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.PostFormValue",
        pattern: SourceKind::MemberAccess("group:revel.Request.PostFormValue"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.PostFormValue (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.Referer",
        pattern: SourceKind::MemberAccess("group:revel.Request.Referer"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.Referer (kind: manual)",
    },
    SourceDef {
        name: "group:revel.Request.UserAgent",
        pattern: SourceKind::MemberAccess("group:revel.Request.UserAgent"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.Request.UserAgent (kind: manual)",
    },
    SourceDef {
        name: "group:revel.ServerWebSocket.MessageReceive",
        pattern: SourceKind::MemberAccess("group:revel.ServerWebSocket.MessageReceive"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.ServerWebSocket.MessageReceive (kind: manual)",
    },
    SourceDef {
        name: "group:revel.ServerWebSocket.MessageReceiveJSON",
        pattern: SourceKind::MemberAccess("group:revel.ServerWebSocket.MessageReceiveJSON"),
        taint_label: "user_input",
        description: "CodeQL source: group:revel.ServerWebSocket.MessageReceiveJSON (kind: manual)",
    },
];

static GROUP_REVEL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "group:revel.Controller.Redirect",
        pattern: SinkKind::FunctionCall("group:revel.Controller.Redirect"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:revel.Controller.Redirect (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:revel.Controller.RenderFileName",
        pattern: SinkKind::FunctionCall("group:revel.Controller.RenderFileName"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:revel.Controller.RenderFileName (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROUP_REVEL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_REVEL_GEN_IMPORTS: &[&str] = &["group:revel"];

pub static GROUP_REVEL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:revel_generated",
    description: "Generated profile for group:revel from CodeQL/Pysa",
    detect_imports: GROUP_REVEL_GEN_IMPORTS,
    sources: GROUP_REVEL_GEN_SOURCES,
    sinks: GROUP_REVEL_GEN_SINKS,
    sanitizers: GROUP_REVEL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
