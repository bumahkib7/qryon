//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static HTML_TEMPLATE_GEN_SOURCES: &[SourceDef] = &[];

static HTML_TEMPLATE_GEN_SINKS: &[SinkDef] = &[];

static HTML_TEMPLATE_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "html/template.HTMLEscape",
        pattern: SanitizerKind::Function("html/template..HTMLEscape"),
        sanitizes: "html",
        description: "CodeQL sanitizer: html/template..HTMLEscape",
    },
    SanitizerDef {
        name: "html/template.HTMLEscapeString",
        pattern: SanitizerKind::Function("html/template..HTMLEscapeString"),
        sanitizes: "html",
        description: "CodeQL sanitizer: html/template..HTMLEscapeString",
    },
    SanitizerDef {
        name: "html/template.JSEscape",
        pattern: SanitizerKind::Function("html/template..JSEscape"),
        sanitizes: "html",
        description: "CodeQL sanitizer: html/template..JSEscape",
    },
    SanitizerDef {
        name: "html/template.JSEscapeString",
        pattern: SanitizerKind::Function("html/template..JSEscapeString"),
        sanitizes: "html",
        description: "CodeQL sanitizer: html/template..JSEscapeString",
    },
];

static HTML_TEMPLATE_GEN_IMPORTS: &[&str] = &["html/template"];

pub static HTML_TEMPLATE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "html_template_generated",
    description: "Generated profile for html/template from CodeQL/Pysa",
    detect_imports: HTML_TEMPLATE_GEN_IMPORTS,
    sources: HTML_TEMPLATE_GEN_SOURCES,
    sinks: HTML_TEMPLATE_GEN_SINKS,
    sanitizers: HTML_TEMPLATE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
