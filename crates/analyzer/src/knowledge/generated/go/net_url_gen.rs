//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static NET_URL_GEN_SOURCES: &[SourceDef] = &[];

static NET_URL_GEN_SINKS: &[SinkDef] = &[];

static NET_URL_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "net/url.PathEscape",
        pattern: SanitizerKind::Function("net/url..PathEscape"),
        sanitizes: "url",
        description: "CodeQL sanitizer: net/url..PathEscape",
    },
    SanitizerDef {
        name: "net/url.PathUnescape",
        pattern: SanitizerKind::Function("net/url..PathUnescape"),
        sanitizes: "url",
        description: "CodeQL sanitizer: net/url..PathUnescape",
    },
    SanitizerDef {
        name: "net/url.QueryEscape",
        pattern: SanitizerKind::Function("net/url..QueryEscape"),
        sanitizes: "sql",
        description: "CodeQL sanitizer: net/url..QueryEscape",
    },
    SanitizerDef {
        name: "net/url.QueryUnescape",
        pattern: SanitizerKind::Function("net/url..QueryUnescape"),
        sanitizes: "sql",
        description: "CodeQL sanitizer: net/url..QueryUnescape",
    },
    SanitizerDef {
        name: "net/url.URL.EscapedPath",
        pattern: SanitizerKind::Function("net/url.URL.EscapedPath"),
        sanitizes: "url",
        description: "CodeQL sanitizer: net/url.URL.EscapedPath",
    },
    SanitizerDef {
        name: "net/url.Values.Encode",
        pattern: SanitizerKind::Function("net/url.Values.Encode"),
        sanitizes: "url",
        description: "CodeQL sanitizer: net/url.Values.Encode",
    },
];

static NET_URL_GEN_IMPORTS: &[&str] = &["net/url"];

pub static NET_URL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "net_url_generated",
    description: "Generated profile for net/url from CodeQL/Pysa",
    detect_imports: NET_URL_GEN_IMPORTS,
    sources: NET_URL_GEN_SOURCES,
    sinks: NET_URL_GEN_SINKS,
    sanitizers: NET_URL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
