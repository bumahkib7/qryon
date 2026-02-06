//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FREEMARKER_GEN_SOURCES: &[SourceDef] = &[];

static FREEMARKER_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "freemarker.cache.StringTemplateLoader.putTemplate",
        pattern: SinkKind::FunctionCall("freemarker.cache.StringTemplateLoader.putTemplate"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: freemarker.cache.StringTemplateLoader.putTemplate (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "freemarker.template.Template.Template",
        pattern: SinkKind::FunctionCall("freemarker.template.Template.Template"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: freemarker.template.Template.Template (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static FREEMARKER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FREEMARKER_GEN_IMPORTS: &[&str] = &["freemarker.cache", "freemarker.template"];

pub static FREEMARKER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "freemarker_generated",
    description: "Generated profile for freemarker.cache from CodeQL/Pysa",
    detect_imports: FREEMARKER_GEN_IMPORTS,
    sources: FREEMARKER_GEN_SOURCES,
    sinks: FREEMARKER_GEN_SINKS,
    sanitizers: FREEMARKER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
