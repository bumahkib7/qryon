//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static FMT_GEN_SOURCES: &[SourceDef] = &[];

static FMT_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "fmt.Print",
        pattern: SinkKind::FunctionCall("fmt.Print"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: fmt..Print (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "fmt.Printf",
        pattern: SinkKind::FunctionCall("fmt.Printf"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: fmt..Printf (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "fmt.Println",
        pattern: SinkKind::FunctionCall("fmt.Println"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: fmt..Println (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static FMT_GEN_SANITIZERS: &[SanitizerDef] = &[];

static FMT_GEN_IMPORTS: &[&str] = &["fmt"];

pub static FMT_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "fmt_generated",
    description: "Generated profile for fmt from CodeQL/Pysa",
    detect_imports: FMT_GEN_IMPORTS,
    sources: FMT_GEN_SOURCES,
    sinks: FMT_GEN_SINKS,
    sanitizers: FMT_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
