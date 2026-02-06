//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static OGNL_GEN_SOURCES: &[SourceDef] = &[];

static OGNL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "ognl.Node.getValue",
        pattern: SinkKind::FunctionCall("ognl.Node.getValue"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: ognl.Node.getValue (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "ognl.Node.setValue",
        pattern: SinkKind::FunctionCall("ognl.Node.setValue"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: ognl.Node.setValue (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "ognl.Ognl.getValue",
        pattern: SinkKind::FunctionCall("ognl.Ognl.getValue"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: ognl.Ognl.getValue (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "ognl.Ognl.setValue",
        pattern: SinkKind::FunctionCall("ognl.Ognl.setValue"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: ognl.Ognl.setValue (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "ognl.enhance.ExpressionAccessor.get",
        pattern: SinkKind::FunctionCall("ognl.enhance.ExpressionAccessor.get"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: ognl.enhance.ExpressionAccessor.get (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "ognl.enhance.ExpressionAccessor.set",
        pattern: SinkKind::FunctionCall("ognl.enhance.ExpressionAccessor.set"),
        rule_id: "java/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: ognl.enhance.ExpressionAccessor.set (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static OGNL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static OGNL_GEN_IMPORTS: &[&str] = &["ognl", "ognl.enhance"];

pub static OGNL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "ognl_generated",
    description: "Generated profile for ognl from CodeQL/Pysa",
    detect_imports: OGNL_GEN_IMPORTS,
    sources: OGNL_GEN_SOURCES,
    sinks: OGNL_GEN_SINKS,
    sanitizers: OGNL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
