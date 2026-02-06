//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static NET_GEN_SOURCES: &[SourceDef] = &[];

static NET_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "net.sf.json.groovy.JsonSlurper.parse",
        pattern: SinkKind::FunctionCall("net.sf.json.groovy.JsonSlurper.parse"),
        rule_id: "java/gen-df-generated",
        severity: Severity::Error,
        description: "CodeQL sink: net.sf.json.groovy.JsonSlurper.parse (kind: df-generated)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "net.schmizz.sshj.SSHClient.authPassword",
        pattern: SinkKind::FunctionCall("net.schmizz.sshj.SSHClient.authPassword"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: net.schmizz.sshj.SSHClient.authPassword (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "net.lingala.zip4j.ZipFile.extractAll",
        pattern: SinkKind::FunctionCall("net.lingala.zip4j.ZipFile.extractAll"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: net.lingala.zip4j.ZipFile.extractAll (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "net.lingala.zip4j.ZipFile.ZipFile",
        pattern: SinkKind::FunctionCall("net.lingala.zip4j.ZipFile.ZipFile"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: net.lingala.zip4j.ZipFile.ZipFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "net.sf.saxon.s9api.Xslt30Transformer.applyTemplates",
        pattern: SinkKind::FunctionCall("net.sf.saxon.s9api.Xslt30Transformer.applyTemplates"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: net.sf.saxon.s9api.Xslt30Transformer.applyTemplates (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "net.sf.saxon.s9api.Xslt30Transformer.callFunction",
        pattern: SinkKind::FunctionCall("net.sf.saxon.s9api.Xslt30Transformer.callFunction"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: net.sf.saxon.s9api.Xslt30Transformer.callFunction (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "net.sf.saxon.s9api.Xslt30Transformer.callTemplate",
        pattern: SinkKind::FunctionCall("net.sf.saxon.s9api.Xslt30Transformer.callTemplate"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: net.sf.saxon.s9api.Xslt30Transformer.callTemplate (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "net.sf.saxon.s9api.Xslt30Transformer.transform",
        pattern: SinkKind::FunctionCall("net.sf.saxon.s9api.Xslt30Transformer.transform"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: net.sf.saxon.s9api.Xslt30Transformer.transform (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "net.sf.saxon.s9api.XsltTransformer.transform",
        pattern: SinkKind::FunctionCall("net.sf.saxon.s9api.XsltTransformer.transform"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: net.sf.saxon.s9api.XsltTransformer.transform (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static NET_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "net.sf.json.util.JSONUtils.stripQuotes",
    pattern: SanitizerKind::Function("net.sf.json.util.JSONUtils.stripQuotes"),
    sanitizes: "general",
    description: "CodeQL sanitizer: net.sf.json.util.JSONUtils.stripQuotes",
}];

static NET_GEN_IMPORTS: &[&str] = &[
    "net.sf.json.groovy",
    "net.sf.json.filters",
    "net.sf.json.regexp",
    "net.sf.json.util",
    "net.sf.json.xml",
    "net.sf.json",
    "net.sf.json.processors",
    "net.sf.json.test",
    "net.schmizz.sshj",
    "net.lingala.zip4j",
    "net.sf.saxon.s9api",
];

pub static NET_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "net_generated",
    description: "Generated profile for net.sf.json.groovy from CodeQL/Pysa",
    detect_imports: NET_GEN_IMPORTS,
    sources: NET_GEN_SOURCES,
    sinks: NET_GEN_SINKS,
    sanitizers: NET_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
