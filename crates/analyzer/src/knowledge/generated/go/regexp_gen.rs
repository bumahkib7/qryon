//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static REGEXP_GEN_SOURCES: &[SourceDef] = &[];

static REGEXP_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "regexp.Compile",
        pattern: SinkKind::FunctionCall("regexp.Compile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: regexp..Compile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "regexp.CompilePOSIX",
        pattern: SinkKind::FunctionCall("regexp.CompilePOSIX"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: regexp..CompilePOSIX (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "regexp.MustCompile",
        pattern: SinkKind::FunctionCall("regexp.MustCompile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: regexp..MustCompile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "regexp.MustCompilePOSIX",
        pattern: SinkKind::FunctionCall("regexp.MustCompilePOSIX"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: regexp..MustCompilePOSIX (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "regexp.Match",
        pattern: SinkKind::FunctionCall("regexp.Match"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: regexp..Match (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "regexp.MatchReader",
        pattern: SinkKind::FunctionCall("regexp.MatchReader"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: regexp..MatchReader (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "regexp.MatchString",
        pattern: SinkKind::FunctionCall("regexp.MatchString"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: regexp..MatchString (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "regexp.Regexp.Match",
        pattern: SinkKind::FunctionCall("regexp.Regexp.Match"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: regexp.Regexp.Match (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "regexp.Regexp.MatchReader",
        pattern: SinkKind::FunctionCall("regexp.Regexp.MatchReader"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: regexp.Regexp.MatchReader (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "regexp.Regexp.MatchString",
        pattern: SinkKind::FunctionCall("regexp.Regexp.MatchString"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: regexp.Regexp.MatchString (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static REGEXP_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "regexp.QuoteMeta",
    pattern: SanitizerKind::Function("regexp..QuoteMeta"),
    sanitizes: "general",
    description: "CodeQL sanitizer: regexp..QuoteMeta",
}];

static REGEXP_GEN_IMPORTS: &[&str] = &["regexp"];

pub static REGEXP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "regexp_generated",
    description: "Generated profile for regexp from CodeQL/Pysa",
    detect_imports: REGEXP_GEN_IMPORTS,
    sources: REGEXP_GEN_SOURCES,
    sinks: REGEXP_GEN_SINKS,
    sanitizers: REGEXP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
