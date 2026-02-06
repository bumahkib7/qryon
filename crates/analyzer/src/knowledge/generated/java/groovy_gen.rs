//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROOVY_GEN_SOURCES: &[SourceDef] = &[];

static GROOVY_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "groovy.util.Eval.me",
        pattern: SinkKind::FunctionCall("groovy.util.Eval.me"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: groovy.util.Eval.me (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "groovy.util.Eval.x",
        pattern: SinkKind::FunctionCall("groovy.util.Eval.x"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: groovy.util.Eval.x (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "groovy.util.Eval.xy",
        pattern: SinkKind::FunctionCall("groovy.util.Eval.xy"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: groovy.util.Eval.xy (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "groovy.util.Eval.xyz",
        pattern: SinkKind::FunctionCall("groovy.util.Eval.xyz"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: groovy.util.Eval.xyz (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "groovy.lang.GroovyClassLoader.parseClass",
        pattern: SinkKind::FunctionCall("groovy.lang.GroovyClassLoader.parseClass"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: groovy.lang.GroovyClassLoader.parseClass (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "groovy.lang.GroovyShell.evaluate",
        pattern: SinkKind::FunctionCall("groovy.lang.GroovyShell.evaluate"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: groovy.lang.GroovyShell.evaluate (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "groovy.lang.GroovyShell.parse",
        pattern: SinkKind::FunctionCall("groovy.lang.GroovyShell.parse"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: groovy.lang.GroovyShell.parse (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "groovy.lang.GroovyShell.run",
        pattern: SinkKind::FunctionCall("groovy.lang.GroovyShell.run"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: groovy.lang.GroovyShell.run (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "groovy.text.TemplateEngine.createTemplate",
        pattern: SinkKind::FunctionCall("groovy.text.TemplateEngine.createTemplate"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: groovy.text.TemplateEngine.createTemplate (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROOVY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROOVY_GEN_IMPORTS: &[&str] = &["groovy.util", "groovy.lang", "groovy.text"];

pub static GROOVY_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "groovy_generated",
    description: "Generated profile for groovy.util from CodeQL/Pysa",
    detect_imports: GROOVY_GEN_IMPORTS,
    sources: GROOVY_GEN_SOURCES,
    sinks: GROOVY_GEN_SINKS,
    sanitizers: GROOVY_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
