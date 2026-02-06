//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static SERDE_DE_IMPLS_PATHBUFVISITOR_AS_SERDE_DE_VISITOR_VISIT_STR_GEN_SOURCES: &[SourceDef] = &[];

static SERDE_DE_IMPLS_PATHBUFVISITOR_AS_SERDE_DE_VISITOR_VISIT_STR_GEN_SINKS: &[SinkDef] =
    &[SinkDef {
        name: "<serde::de::impls::PathBufVisitor as serde::de::Visitor>::visit_str.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "rust/gen-alloc-layout",
        severity: Severity::Error,
        description: "CodeQL sink: Argument[0] (kind: alloc-layout)",
        cwe: Some("CWE-74"),
    }];

static SERDE_DE_IMPLS_PATHBUFVISITOR_AS_SERDE_DE_VISITOR_VISIT_STR_GEN_SANITIZERS:
    &[SanitizerDef] = &[];

static SERDE_DE_IMPLS_PATHBUFVISITOR_AS_SERDE_DE_VISITOR_VISIT_STR_GEN_IMPORTS: &[&str] =
    &["<serde::de::impls::PathBufVisitor as serde::de::Visitor>::visit_str"];

pub static SERDE_DE_IMPLS_PATHBUFVISITOR_AS_SERDE_DE_VISITOR_VISIT_STR_GEN_PROFILE:
    FrameworkProfile = FrameworkProfile {
    name: "<serde::de::impls::pathbufvisitor as serde::de::visitor>::visit_str_generated",
    description: "Generated profile for <serde::de::impls::PathBufVisitor as serde::de::Visitor>::visit_str from CodeQL/Pysa",
    detect_imports: SERDE_DE_IMPLS_PATHBUFVISITOR_AS_SERDE_DE_VISITOR_VISIT_STR_GEN_IMPORTS,
    sources: SERDE_DE_IMPLS_PATHBUFVISITOR_AS_SERDE_DE_VISITOR_VISIT_STR_GEN_SOURCES,
    sinks: SERDE_DE_IMPLS_PATHBUFVISITOR_AS_SERDE_DE_VISITOR_VISIT_STR_GEN_SINKS,
    sanitizers: SERDE_DE_IMPLS_PATHBUFVISITOR_AS_SERDE_DE_VISITOR_VISIT_STR_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
