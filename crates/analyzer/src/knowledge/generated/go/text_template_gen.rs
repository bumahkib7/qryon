//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static TEXT_TEMPLATE_GEN_SOURCES: &[SourceDef] = &[];

static TEXT_TEMPLATE_GEN_SINKS: &[SinkDef] = &[];

static TEXT_TEMPLATE_GEN_SANITIZERS: &[SanitizerDef] = &[
    SanitizerDef {
        name: "text/template.HTMLEscape",
        pattern: SanitizerKind::Function("text/template..HTMLEscape"),
        sanitizes: "html",
        description: "CodeQL sanitizer: text/template..HTMLEscape",
    },
    SanitizerDef {
        name: "text/template.HTMLEscapeString",
        pattern: SanitizerKind::Function("text/template..HTMLEscapeString"),
        sanitizes: "html",
        description: "CodeQL sanitizer: text/template..HTMLEscapeString",
    },
    SanitizerDef {
        name: "text/template.JSEscape",
        pattern: SanitizerKind::Function("text/template..JSEscape"),
        sanitizes: "general",
        description: "CodeQL sanitizer: text/template..JSEscape",
    },
    SanitizerDef {
        name: "text/template.JSEscapeString",
        pattern: SanitizerKind::Function("text/template..JSEscapeString"),
        sanitizes: "general",
        description: "CodeQL sanitizer: text/template..JSEscapeString",
    },
];

static TEXT_TEMPLATE_GEN_IMPORTS: &[&str] = &["text/template"];

pub static TEXT_TEMPLATE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "text_template_generated",
    description: "Generated profile for text/template from CodeQL/Pysa",
    detect_imports: TEXT_TEMPLATE_GEN_IMPORTS,
    sources: TEXT_TEMPLATE_GEN_SOURCES,
    sinks: TEXT_TEMPLATE_GEN_SINKS,
    sanitizers: TEXT_TEMPLATE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
