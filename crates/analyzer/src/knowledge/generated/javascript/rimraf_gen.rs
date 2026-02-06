//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static RIMRAF_GEN_SOURCES: &[SourceDef] = &[];

static RIMRAF_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "rimraf.Member[sync,native,manual,windows,moveRemove,posix].Argument[0]",
        pattern: SinkKind::FunctionCall("sync,native,manual,windows,moveRemove,posix"),
        rule_id: "javascript/gen-path-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Member[sync,native,manual,windows,moveRemove,posix].Argument[0] (kind: path-injection)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "rimraf.Member[Sync,nativeSync,manualSync,windowsSync,moveRemoveSync,posixSync].Argument[0]",
        pattern: SinkKind::FunctionCall(
            "rimrafSync,nativeSync,manualSync,windowsSync,moveRemoveSync,posixSync",
        ),
        rule_id: "javascript/gen-path-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Member[rimrafSync,nativeSync,manualSync,windowsSync,moveRemoveSync,posixSync].Argument[0] (kind: path-injection)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "rimraf.Member[native,manual,windows,moveRemove,posix].Member[sync].Argument[0]",
        pattern: SinkKind::FunctionCall("native,manual,windows,moveRemove,posix.sync"),
        rule_id: "javascript/gen-path-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Member[native,manual,windows,moveRemove,posix].Member[sync].Argument[0] (kind: path-injection)",
        cwe: Some("CWE-22"),
    },
];

static RIMRAF_GEN_SANITIZERS: &[SanitizerDef] = &[];

static RIMRAF_GEN_IMPORTS: &[&str] = &["rimraf"];

pub static RIMRAF_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "rimraf_generated",
    description: "Generated profile for rimraf from CodeQL/Pysa",
    detect_imports: RIMRAF_GEN_IMPORTS,
    sources: RIMRAF_GEN_SOURCES,
    sinks: RIMRAF_GEN_SINKS,
    sanitizers: RIMRAF_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
