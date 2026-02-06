//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static WINDOWS_GEN_SOURCES: &[SourceDef] = &[];

static WINDOWS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "Windows.Security.Cryptography.Core.SymmetricKeyAlgorithmProvider.CreateSymmetricKey",
    pattern: SinkKind::FunctionCall(
        "Windows.Security.Cryptography.Core.SymmetricKeyAlgorithmProvider.CreateSymmetricKey",
    ),
    rule_id: "csharp/gen-manual",
    severity: Severity::Error,
    description: "CodeQL sink: Windows.Security.Cryptography.Core.SymmetricKeyAlgorithmProvider.CreateSymmetricKey (kind: manual)",
    cwe: Some("CWE-74"),
}];

static WINDOWS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static WINDOWS_GEN_IMPORTS: &[&str] = &["Windows.Security.Cryptography.Core"];

pub static WINDOWS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "windows_generated",
    description: "Generated profile for Windows.Security.Cryptography.Core from CodeQL/Pysa",
    detect_imports: WINDOWS_GEN_IMPORTS,
    sources: WINDOWS_GEN_SOURCES,
    sinks: WINDOWS_GEN_SINKS,
    sanitizers: WINDOWS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
