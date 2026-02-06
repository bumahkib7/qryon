//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_OS_STR_BYTES_SLICE_CHECK_PUBLIC_BOUNDARY_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYS_OS_STR_BYTES_SLICE_CHECK_PUBLIC_BOUNDARY_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::sys::os_str::bytes::Slice>::check_public_boundary.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-log-injection",
    severity: Severity::Warning,
    description: "CodeQL sink: Argument[0] (kind: log-injection)",
    cwe: Some("CWE-117"),
}];

static STD_SYS_OS_STR_BYTES_SLICE_CHECK_PUBLIC_BOUNDARY_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_OS_STR_BYTES_SLICE_CHECK_PUBLIC_BOUNDARY_GEN_IMPORTS: &[&str] =
    &["<std::sys::os_str::bytes::Slice>::check_public_boundary"];

pub static STD_SYS_OS_STR_BYTES_SLICE_CHECK_PUBLIC_BOUNDARY_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::sys::os_str::bytes::slice>::check_public_boundary_generated",
        description: "Generated profile for <std::sys::os_str::bytes::Slice>::check_public_boundary from CodeQL/Pysa",
        detect_imports: STD_SYS_OS_STR_BYTES_SLICE_CHECK_PUBLIC_BOUNDARY_GEN_IMPORTS,
        sources: STD_SYS_OS_STR_BYTES_SLICE_CHECK_PUBLIC_BOUNDARY_GEN_SOURCES,
        sinks: STD_SYS_OS_STR_BYTES_SLICE_CHECK_PUBLIC_BOUNDARY_GEN_SINKS,
        sanitizers: STD_SYS_OS_STR_BYTES_SLICE_CHECK_PUBLIC_BOUNDARY_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
