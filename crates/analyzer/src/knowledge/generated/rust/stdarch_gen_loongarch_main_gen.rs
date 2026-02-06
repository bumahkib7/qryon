//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STDARCH_GEN_LOONGARCH_MAIN_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "stdarch-gen-loongarch::main.ReturnValue",
    pattern: SourceKind::FunctionCall(""),
    taint_label: "file_input",
    description: "CodeQL source: ReturnValue (kind: file)",
}];

static STDARCH_GEN_LOONGARCH_MAIN_GEN_SINKS: &[SinkDef] = &[];

static STDARCH_GEN_LOONGARCH_MAIN_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STDARCH_GEN_LOONGARCH_MAIN_GEN_IMPORTS: &[&str] = &["stdarch-gen-loongarch::main"];

pub static STDARCH_GEN_LOONGARCH_MAIN_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "stdarch_gen_loongarch::main_generated",
    description: "Generated profile for stdarch-gen-loongarch::main from CodeQL/Pysa",
    detect_imports: STDARCH_GEN_LOONGARCH_MAIN_GEN_IMPORTS,
    sources: STDARCH_GEN_LOONGARCH_MAIN_GEN_SOURCES,
    sinks: STDARCH_GEN_LOONGARCH_MAIN_GEN_SINKS,
    sanitizers: STDARCH_GEN_LOONGARCH_MAIN_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
