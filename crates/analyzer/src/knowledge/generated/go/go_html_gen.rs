//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GO_HTML_GEN_SOURCES: &[SourceDef] = &[];

static GO_HTML_GEN_SINKS: &[SinkDef] = &[];

static GO_HTML_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "html.EscapeString",
        pattern: SanitizerKind::Function("html..EscapeString"),
        sanitizes: "html",
        description: "CodeQL sanitizer: html..EscapeString",
    },
    SanitizerDef {
        name: "html.UnescapeString",
        pattern: SanitizerKind::Function("html..UnescapeString"),
        sanitizes: "html",
        description: "CodeQL sanitizer: html..UnescapeString",
    },
];

static GO_HTML_GEN_IMPORTS: &[&str] = &["html"];

pub static GO_HTML_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "go_html_generated",
    description: "Generated profile for html from CodeQL/Pysa",
    detect_imports: GO_HTML_GEN_IMPORTS,
    sources: GO_HTML_GEN_SOURCES,
    sinks: GO_HTML_GEN_SINKS,
    sanitizers: GO_HTML_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
