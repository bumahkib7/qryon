//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ILCOMPILER_GEN_SOURCES: &[SourceDef] = &[];

static ILCOMPILER_GEN_SINKS: &[SinkDef] = &[];

static ILCOMPILER_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "ILCompiler.Reflection.ReadyToRun.StringBuilderExtensions.AppendEscapedString",
    pattern: SanitizerKind::Function(
        "ILCompiler.Reflection.ReadyToRun.StringBuilderExtensions.AppendEscapedString",
    ),
    sanitizes: "general",
    description: "CodeQL sanitizer: ILCompiler.Reflection.ReadyToRun.StringBuilderExtensions.AppendEscapedString",
}];

static ILCOMPILER_GEN_IMPORTS: &[&str] = &[
    "ILCompiler.IBC",
    "ILCompiler.Reflection.ReadyToRun.x86",
    "ILCompiler",
    "ILCompiler.Reflection.ReadyToRun",
    "ILCompiler.Reflection.ReadyToRun.Arm",
    "ILCompiler.Reflection.ReadyToRun.LoongArch64",
    "ILCompiler.Reflection.ReadyToRun.MachO",
    "ILCompiler.Reflection.ReadyToRun.Amd64",
    "ILCompiler.Reflection.ReadyToRun.Arm64",
    "ILCompiler.Reflection.ReadyToRun.RiscV64",
];

pub static ILCOMPILER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "ilcompiler_generated",
    description: "Generated profile for ILCompiler.IBC from CodeQL/Pysa",
    detect_imports: ILCOMPILER_GEN_IMPORTS,
    sources: ILCOMPILER_GEN_SOURCES,
    sinks: ILCOMPILER_GEN_SINKS,
    sanitizers: ILCOMPILER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
