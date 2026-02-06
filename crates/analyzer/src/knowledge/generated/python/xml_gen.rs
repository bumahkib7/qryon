//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static XML_GEN_SOURCES: &[SourceDef] = &[];

static XML_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "xml.etree.ElementTree.parse",
        pattern: SinkKind::FunctionCall("xml.etree.ElementTree.parse"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: xml.etree.ElementTree.parse (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "xml.etree.ElementTree.iterparse",
        pattern: SinkKind::FunctionCall("xml.etree.ElementTree.iterparse"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: xml.etree.ElementTree.iterparse (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "xml.etree.ElementTree.XML",
        pattern: SinkKind::FunctionCall("xml.etree.ElementTree.XML"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: xml.etree.ElementTree.XML (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "xml.etree.ElementTree.XMLParser.feed",
        pattern: SinkKind::FunctionCall("xml.etree.ElementTree.XMLParser.feed"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: xml.etree.ElementTree.XMLParser.feed (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "xml.dom.minidom.parse",
        pattern: SinkKind::FunctionCall("xml.dom.minidom.parse"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: xml.dom.minidom.parse (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "xml.dom.minidom.parseString",
        pattern: SinkKind::FunctionCall("xml.dom.minidom.parseString"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: xml.dom.minidom.parseString (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "xml.dom.pulldom.parse",
        pattern: SinkKind::FunctionCall("xml.dom.pulldom.parse"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: xml.dom.pulldom.parse (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "xml.dom.pulldom.parseString",
        pattern: SinkKind::FunctionCall("xml.dom.pulldom.parseString"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: xml.dom.pulldom.parseString (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
];

static XML_GEN_SANITIZERS: &[SanitizerDef] = &[];

static XML_GEN_IMPORTS: &[&str] = &["xml"];

pub static XML_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "xml_generated",
    description: "Generated profile for xml from CodeQL/Pysa",
    detect_imports: XML_GEN_IMPORTS,
    sources: XML_GEN_SOURCES,
    sinks: XML_GEN_SINKS,
    sanitizers: XML_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
