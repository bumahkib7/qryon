//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_IO_ERROR_REPR_BITPACKED_REPR_NEW_OS_GEN_SOURCES: &[SourceDef] = &[];

static STD_IO_ERROR_REPR_BITPACKED_REPR_NEW_OS_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::io::error::repr_bitpacked::Repr>::new_os.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static STD_IO_ERROR_REPR_BITPACKED_REPR_NEW_OS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_IO_ERROR_REPR_BITPACKED_REPR_NEW_OS_GEN_IMPORTS: &[&str] =
    &["<std::io::error::repr_bitpacked::Repr>::new_os"];

pub static STD_IO_ERROR_REPR_BITPACKED_REPR_NEW_OS_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::io::error::repr_bitpacked::repr>::new_os_generated",
        description: "Generated profile for <std::io::error::repr_bitpacked::Repr>::new_os from CodeQL/Pysa",
        detect_imports: STD_IO_ERROR_REPR_BITPACKED_REPR_NEW_OS_GEN_IMPORTS,
        sources: STD_IO_ERROR_REPR_BITPACKED_REPR_NEW_OS_GEN_SOURCES,
        sinks: STD_IO_ERROR_REPR_BITPACKED_REPR_NEW_OS_GEN_SINKS,
        sanitizers: STD_IO_ERROR_REPR_BITPACKED_REPR_NEW_OS_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
