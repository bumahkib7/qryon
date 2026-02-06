//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LXML_GEN_SOURCES: &[SourceDef] = &[];

static LXML_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "lxml.etree.fromstring",
        pattern: SinkKind::FunctionCall("lxml.etree.fromstring"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: lxml.etree.fromstring (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "lxml.etree.parse",
        pattern: SinkKind::FunctionCall("lxml.etree.parse"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: lxml.etree.parse (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "lxml.etree.fromstringlist",
        pattern: SinkKind::FunctionCall("lxml.etree.fromstringlist"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: lxml.etree.fromstringlist (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
];

static LXML_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LXML_GEN_IMPORTS: &[&str] = &["lxml"];

pub static LXML_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "lxml_generated",
    description: "Generated profile for lxml from CodeQL/Pysa",
    detect_imports: LXML_GEN_IMPORTS,
    sources: LXML_GEN_SOURCES,
    sinks: LXML_GEN_SINKS,
    sanitizers: LXML_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
