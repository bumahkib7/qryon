//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static GROUP_GOKOGIRI_XML_GEN_SOURCES: &[SourceDef] = &[];

static GROUP_GOKOGIRI_XML_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "group:gokogiri/xml.Node.Search",
        pattern: SinkKind::FunctionCall("group:gokogiri/xml.Node.Search"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gokogiri/xml.Node.Search (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gokogiri/xml.Node.SearchWithVariables",
        pattern: SinkKind::FunctionCall("group:gokogiri/xml.Node.SearchWithVariables"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gokogiri/xml.Node.SearchWithVariables (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gokogiri/xml.Node.EvalXPath",
        pattern: SinkKind::FunctionCall("group:gokogiri/xml.Node.EvalXPath"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gokogiri/xml.Node.EvalXPath (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "group:gokogiri/xml.Node.EvalXPathAsBoolean",
        pattern: SinkKind::FunctionCall("group:gokogiri/xml.Node.EvalXPathAsBoolean"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: group:gokogiri/xml.Node.EvalXPathAsBoolean (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static GROUP_GOKOGIRI_XML_GEN_SANITIZERS: &[SanitizerDef] = &[];

static GROUP_GOKOGIRI_XML_GEN_IMPORTS: &[&str] = &["group:gokogiri/xml"];

pub static GROUP_GOKOGIRI_XML_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "group:gokogiri_xml_generated",
    description: "Generated profile for group:gokogiri/xml from CodeQL/Pysa",
    detect_imports: GROUP_GOKOGIRI_XML_GEN_IMPORTS,
    sources: GROUP_GOKOGIRI_XML_GEN_SOURCES,
    sinks: GROUP_GOKOGIRI_XML_GEN_SINKS,
    sanitizers: GROUP_GOKOGIRI_XML_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
