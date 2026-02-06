//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static NET_HTTP_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "net/http.Request.Cookie",
        pattern: SourceKind::MemberAccess("net/http.Request.Cookie"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.Cookie (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.Cookies",
        pattern: SourceKind::MemberAccess("net/http.Request.Cookies"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.Cookies (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.FormFile",
        pattern: SourceKind::MemberAccess("net/http.Request.FormFile"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.FormFile (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.FormValue",
        pattern: SourceKind::MemberAccess("net/http.Request.FormValue"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.FormValue (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.MultipartReader",
        pattern: SourceKind::MemberAccess("net/http.Request.MultipartReader"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.MultipartReader (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.PostFormValue",
        pattern: SourceKind::MemberAccess("net/http.Request.PostFormValue"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.PostFormValue (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.Referer",
        pattern: SourceKind::MemberAccess("net/http.Request.Referer"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.Referer (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.UserAgent",
        pattern: SourceKind::MemberAccess("net/http.Request.UserAgent"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.UserAgent (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.Body",
        pattern: SourceKind::MemberAccess("net/http.Request.Body"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.Body (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.GetBody",
        pattern: SourceKind::MemberAccess("net/http.Request.GetBody"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.GetBody (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.Form",
        pattern: SourceKind::MemberAccess("net/http.Request.Form"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.Form (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.PostForm",
        pattern: SourceKind::MemberAccess("net/http.Request.PostForm"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.PostForm (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.MultipartForm",
        pattern: SourceKind::MemberAccess("net/http.Request.MultipartForm"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.MultipartForm (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.Header",
        pattern: SourceKind::MemberAccess("net/http.Request.Header"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.Header (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.Trailer",
        pattern: SourceKind::MemberAccess("net/http.Request.Trailer"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.Trailer (kind: manual)",
    },
    SourceDef {
        name: "net/http.Request.URL",
        pattern: SourceKind::MemberAccess("net/http.Request.URL"),
        taint_label: "user_input",
        description: "CodeQL source: net/http.Request.URL (kind: manual)",
    },
];

static NET_HTTP_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "net/http.ServeFile",
        pattern: SinkKind::FunctionCall("net/http.ServeFile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: net/http..ServeFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "net/http.Redirect",
        pattern: SinkKind::FunctionCall("net/http.Redirect"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: net/http..Redirect (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static NET_HTTP_GEN_SANITIZERS: &[SanitizerDef] = &[];

static NET_HTTP_GEN_IMPORTS: &[&str] = &["net/http"];

pub static NET_HTTP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "net_http_generated",
    description: "Generated profile for net/http from CodeQL/Pysa",
    detect_imports: NET_HTTP_GEN_IMPORTS,
    sources: NET_HTTP_GEN_SOURCES,
    sinks: NET_HTTP_GEN_SINKS,
    sanitizers: NET_HTTP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
