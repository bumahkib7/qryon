//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MARKDOWN_GEN_SOURCES: &[SourceDef] = &[];

static MARKDOWN_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "markdown.core.markdown",
        pattern: SinkKind::FunctionCall("markdown.core.markdown"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: markdown.core.markdown (kind: XSS)",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "markdown.core.markdownFromFile",
        pattern: SinkKind::FunctionCall("markdown.core.markdownFromFile"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: markdown.core.markdownFromFile (kind: XSS)",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "markdown.core.Markdown.convert",
        pattern: SinkKind::FunctionCall("markdown.core.Markdown.convert"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: markdown.core.Markdown.convert (kind: XSS)",
        cwe: Some("CWE-79"),
    },
    SinkDef {
        name: "markdown.core.Markdown.convertFile",
        pattern: SinkKind::FunctionCall("markdown.core.Markdown.convertFile"),
        rule_id: "python/gen-pysa-xss",
        severity: Severity::Critical,
        description: "Pysa sink: markdown.core.Markdown.convertFile (kind: XSS)",
        cwe: Some("CWE-79"),
    },
];

static MARKDOWN_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MARKDOWN_GEN_IMPORTS: &[&str] = &["markdown"];

pub static MARKDOWN_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "markdown_generated",
    description: "Generated profile for markdown from CodeQL/Pysa",
    detect_imports: MARKDOWN_GEN_IMPORTS,
    sources: MARKDOWN_GEN_SOURCES,
    sinks: MARKDOWN_GEN_SINKS,
    sanitizers: MARKDOWN_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
