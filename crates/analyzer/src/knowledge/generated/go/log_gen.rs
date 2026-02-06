//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static LOG_GEN_SOURCES: &[SourceDef] = &[];

static LOG_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "log.Fatal",
        pattern: SinkKind::FunctionCall("log.Fatal"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log..Fatal (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Fatalf",
        pattern: SinkKind::FunctionCall("log.Fatalf"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log..Fatalf (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Fatalln",
        pattern: SinkKind::FunctionCall("log.Fatalln"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log..Fatalln (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Output",
        pattern: SinkKind::FunctionCall("log.Output"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log..Output (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Panic",
        pattern: SinkKind::FunctionCall("log.Panic"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log..Panic (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Panicf",
        pattern: SinkKind::FunctionCall("log.Panicf"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log..Panicf (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Panicln",
        pattern: SinkKind::FunctionCall("log.Panicln"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log..Panicln (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Print",
        pattern: SinkKind::FunctionCall("log.Print"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log..Print (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Printf",
        pattern: SinkKind::FunctionCall("log.Printf"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log..Printf (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Println",
        pattern: SinkKind::FunctionCall("log.Println"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log..Println (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Logger.Fatal",
        pattern: SinkKind::FunctionCall("log.Logger.Fatal"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log.Logger.Fatal (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Logger.Fatalf",
        pattern: SinkKind::FunctionCall("log.Logger.Fatalf"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log.Logger.Fatalf (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Logger.Fatalln",
        pattern: SinkKind::FunctionCall("log.Logger.Fatalln"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log.Logger.Fatalln (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Logger.Output",
        pattern: SinkKind::FunctionCall("log.Logger.Output"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log.Logger.Output (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Logger.Panic",
        pattern: SinkKind::FunctionCall("log.Logger.Panic"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log.Logger.Panic (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Logger.Panicf",
        pattern: SinkKind::FunctionCall("log.Logger.Panicf"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log.Logger.Panicf (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Logger.Panicln",
        pattern: SinkKind::FunctionCall("log.Logger.Panicln"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log.Logger.Panicln (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Logger.Print",
        pattern: SinkKind::FunctionCall("log.Logger.Print"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log.Logger.Print (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Logger.Printf",
        pattern: SinkKind::FunctionCall("log.Logger.Printf"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log.Logger.Printf (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "log.Logger.Println",
        pattern: SinkKind::FunctionCall("log.Logger.Println"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: log.Logger.Println (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static LOG_GEN_SANITIZERS: &[SanitizerDef] = &[];

static LOG_GEN_IMPORTS: &[&str] = &["log"];

pub static LOG_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "log_generated",
    description: "Generated profile for log from CodeQL/Pysa",
    detect_imports: LOG_GEN_IMPORTS,
    sources: LOG_GEN_SOURCES,
    sinks: LOG_GEN_SINKS,
    sanitizers: LOG_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
