//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static IO_IOUTIL_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "io/ioutil.ReadFile",
    pattern: SourceKind::MemberAccess("io/ioutil.ReadFile"),
    taint_label: "user_input",
    description: "CodeQL source: io/ioutil..ReadFile (kind: manual)",
}];

static IO_IOUTIL_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "io/ioutil.ReadDir",
        pattern: SinkKind::FunctionCall("io/ioutil.ReadDir"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io/ioutil..ReadDir (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io/ioutil.ReadFile",
        pattern: SinkKind::FunctionCall("io/ioutil.ReadFile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io/ioutil..ReadFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io/ioutil.TempDir",
        pattern: SinkKind::FunctionCall("io/ioutil.TempDir"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io/ioutil..TempDir (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io/ioutil.TempFile",
        pattern: SinkKind::FunctionCall("io/ioutil.TempFile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io/ioutil..TempFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "io/ioutil.WriteFile",
        pattern: SinkKind::FunctionCall("io/ioutil.WriteFile"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: io/ioutil..WriteFile (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static IO_IOUTIL_GEN_SANITIZERS: &[SanitizerDef] = &[];

static IO_IOUTIL_GEN_IMPORTS: &[&str] = &["io/ioutil"];

pub static IO_IOUTIL_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "io_ioutil_generated",
    description: "Generated profile for io/ioutil from CodeQL/Pysa",
    detect_imports: IO_IOUTIL_GEN_IMPORTS,
    sources: IO_IOUTIL_GEN_SOURCES,
    sinks: IO_IOUTIL_GEN_SINKS,
    sanitizers: IO_IOUTIL_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
