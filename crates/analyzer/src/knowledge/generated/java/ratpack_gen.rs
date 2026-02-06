//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static RATPACK_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "ratpack.http.Request.getBody",
        pattern: SourceKind::MemberAccess("ratpack.http.Request.getBody"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.http.Request.getBody (kind: manual)",
    },
    SourceDef {
        name: "ratpack.http.Request.getContentLength",
        pattern: SourceKind::MemberAccess("ratpack.http.Request.getContentLength"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.http.Request.getContentLength (kind: manual)",
    },
    SourceDef {
        name: "ratpack.http.Request.getCookies",
        pattern: SourceKind::MemberAccess("ratpack.http.Request.getCookies"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.http.Request.getCookies (kind: manual)",
    },
    SourceDef {
        name: "ratpack.http.Request.getHeaders",
        pattern: SourceKind::MemberAccess("ratpack.http.Request.getHeaders"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.http.Request.getHeaders (kind: manual)",
    },
    SourceDef {
        name: "ratpack.http.Request.getPath",
        pattern: SourceKind::MemberAccess("ratpack.http.Request.getPath"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.http.Request.getPath (kind: manual)",
    },
    SourceDef {
        name: "ratpack.http.Request.getQuery",
        pattern: SourceKind::MemberAccess("ratpack.http.Request.getQuery"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.http.Request.getQuery (kind: manual)",
    },
    SourceDef {
        name: "ratpack.http.Request.getQueryParams",
        pattern: SourceKind::MemberAccess("ratpack.http.Request.getQueryParams"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.http.Request.getQueryParams (kind: manual)",
    },
    SourceDef {
        name: "ratpack.http.Request.getRawUri",
        pattern: SourceKind::MemberAccess("ratpack.http.Request.getRawUri"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.http.Request.getRawUri (kind: manual)",
    },
    SourceDef {
        name: "ratpack.http.Request.getUri",
        pattern: SourceKind::MemberAccess("ratpack.http.Request.getUri"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.http.Request.getUri (kind: manual)",
    },
    SourceDef {
        name: "ratpack.http.Request.oneCookie",
        pattern: SourceKind::MemberAccess("ratpack.http.Request.oneCookie"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.http.Request.oneCookie (kind: manual)",
    },
    SourceDef {
        name: "ratpack.handling.Context.parse",
        pattern: SourceKind::MemberAccess("ratpack.handling.Context.parse"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.handling.Context.parse (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.handling.Context.parse",
        pattern: SourceKind::MemberAccess("ratpack.core.handling.Context.parse"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.handling.Context.parse (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.http.Request.getBody",
        pattern: SourceKind::MemberAccess("ratpack.core.http.Request.getBody"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.http.Request.getBody (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.http.Request.getContentLength",
        pattern: SourceKind::MemberAccess("ratpack.core.http.Request.getContentLength"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.http.Request.getContentLength (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.http.Request.getCookies",
        pattern: SourceKind::MemberAccess("ratpack.core.http.Request.getCookies"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.http.Request.getCookies (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.http.Request.getHeaders",
        pattern: SourceKind::MemberAccess("ratpack.core.http.Request.getHeaders"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.http.Request.getHeaders (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.http.Request.getPath",
        pattern: SourceKind::MemberAccess("ratpack.core.http.Request.getPath"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.http.Request.getPath (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.http.Request.getQuery",
        pattern: SourceKind::MemberAccess("ratpack.core.http.Request.getQuery"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.http.Request.getQuery (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.http.Request.getQueryParams",
        pattern: SourceKind::MemberAccess("ratpack.core.http.Request.getQueryParams"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.http.Request.getQueryParams (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.http.Request.getRawUri",
        pattern: SourceKind::MemberAccess("ratpack.core.http.Request.getRawUri"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.http.Request.getRawUri (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.http.Request.getUri",
        pattern: SourceKind::MemberAccess("ratpack.core.http.Request.getUri"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.http.Request.getUri (kind: manual)",
    },
    SourceDef {
        name: "ratpack.core.http.Request.oneCookie",
        pattern: SourceKind::MemberAccess("ratpack.core.http.Request.oneCookie"),
        taint_label: "user_input",
        description: "CodeQL source: ratpack.core.http.Request.oneCookie (kind: manual)",
    },
];

static RATPACK_GEN_SINKS: &[SinkDef] = &[];

static RATPACK_GEN_SANITIZERS: &[SanitizerDef] = &[];

static RATPACK_GEN_IMPORTS: &[&str] = &[
    "ratpack.http",
    "ratpack.form",
    "ratpack.exec",
    "ratpack.handling",
    "ratpack.core.form",
    "ratpack.core.handling",
    "ratpack.core.http",
    "ratpack.util",
    "ratpack.func",
];

pub static RATPACK_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "ratpack_generated",
    description: "Generated profile for ratpack.http from CodeQL/Pysa",
    detect_imports: RATPACK_GEN_IMPORTS,
    sources: RATPACK_GEN_SOURCES,
    sinks: RATPACK_GEN_SINKS,
    sanitizers: RATPACK_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
