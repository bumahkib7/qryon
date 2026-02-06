//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static JAVAFX_GEN_SOURCES: &[SourceDef] = &[];

static JAVAFX_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "javafx.scene.web.WebEngine.load",
    pattern: SinkKind::FunctionCall("javafx.scene.web.WebEngine.load"),
    rule_id: "java/gen-ai-manual",
    severity: Severity::Error,
    description: "CodeQL sink: javafx.scene.web.WebEngine.load (kind: ai-manual)",
    cwe: Some("CWE-74"),
}];

static JAVAFX_GEN_SANITIZERS: &[SanitizerDef] = &[];

static JAVAFX_GEN_IMPORTS: &[&str] = &["javafx.scene.web"];

pub static JAVAFX_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "javafx_generated",
    description: "Generated profile for javafx.scene.web from CodeQL/Pysa",
    detect_imports: JAVAFX_GEN_IMPORTS,
    sources: JAVAFX_GEN_SOURCES,
    sinks: JAVAFX_GEN_SINKS,
    sanitizers: JAVAFX_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
