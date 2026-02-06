//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static MKDIRP_GEN_SOURCES: &[SourceDef] = &[];

static MKDIRP_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "mkdirp.Member[nativeSync,native,manual,manualSync,Native,Manual,ManualSync,NativeSync,Sync,sync].Argument[0]",
        pattern: SinkKind::FunctionCall(
            "nativeSync,native,manual,manualSync,mkdirpNative,mkdirpManual,mkdirpManualSync,mkdirpNativeSync,mkdirpSync,sync",
        ),
        rule_id: "javascript/gen-path-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Member[nativeSync,native,manual,manualSync,mkdirpNative,mkdirpManual,mkdirpManualSync,mkdirpNativeSync,mkdirpSync,sync].Argument[0] (kind: path-injection)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "mkdirp.Argument[0]",
        pattern: SinkKind::FunctionCall(""),
        rule_id: "javascript/gen-path-injection",
        severity: Severity::Critical,
        description: "CodeQL sink: Argument[0] (kind: path-injection)",
        cwe: Some("CWE-22"),
    },
];

static MKDIRP_GEN_SANITIZERS: &[SanitizerDef] = &[];

static MKDIRP_GEN_IMPORTS: &[&str] = &["mkdirp"];

pub static MKDIRP_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "mkdirp_generated",
    description: "Generated profile for mkdirp from CodeQL/Pysa",
    detect_imports: MKDIRP_GEN_IMPORTS,
    sources: MKDIRP_GEN_SOURCES,
    sinks: MKDIRP_GEN_SINKS,
    sanitizers: MKDIRP_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
