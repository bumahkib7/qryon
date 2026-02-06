//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static DEFUSEDXML_GEN_SOURCES: &[SourceDef] = &[];

static DEFUSEDXML_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "defusedxml.lxml.fromstring",
        pattern: SinkKind::FunctionCall("defusedxml.lxml.fromstring"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: defusedxml.lxml.fromstring (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "defusedxml.lxml.parse",
        pattern: SinkKind::FunctionCall("defusedxml.lxml.parse"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: defusedxml.lxml.parse (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "defusedxml.ElementTree.parse",
        pattern: SinkKind::FunctionCall("defusedxml.ElementTree.parse"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: defusedxml.ElementTree.parse (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "defusedxml.ElementTree.iterparse",
        pattern: SinkKind::FunctionCall("defusedxml.ElementTree.iterparse"),
        rule_id: "python/gen-pysa-xmlparser",
        severity: Severity::Error,
        description: "Pysa sink: defusedxml.ElementTree.iterparse (kind: XMLParser)",
        cwe: Some("CWE-74"),
    },
];

static DEFUSEDXML_GEN_SANITIZERS: &[SanitizerDef] = &[];

static DEFUSEDXML_GEN_IMPORTS: &[&str] = &["defusedxml"];

pub static DEFUSEDXML_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "defusedxml_generated",
    description: "Generated profile for defusedxml from CodeQL/Pysa",
    detect_imports: DEFUSEDXML_GEN_IMPORTS,
    sources: DEFUSEDXML_GEN_SOURCES,
    sinks: DEFUSEDXML_GEN_SINKS,
    sanitizers: DEFUSEDXML_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
