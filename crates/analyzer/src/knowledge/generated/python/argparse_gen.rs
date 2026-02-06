//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static ARGPARSE_GEN_SOURCES: &[SourceDef] = &[SourceDef {
    name: "argparse.ArgumentParser.parse_args",
    pattern: SourceKind::MemberAccess("argparse.ArgumentParser.parse_args"),
    taint_label: "user_input",
    description: "Pysa source: argparse.ArgumentParser.parse_args (kind: CLIUserControlled)",
}];

static ARGPARSE_GEN_SINKS: &[SinkDef] = &[];

static ARGPARSE_GEN_SANITIZERS: &[SanitizerDef] = &[];

static ARGPARSE_GEN_IMPORTS: &[&str] = &["argparse"];

pub static ARGPARSE_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "argparse_generated",
    description: "Generated profile for argparse from CodeQL/Pysa",
    detect_imports: ARGPARSE_GEN_IMPORTS,
    sources: ARGPARSE_GEN_SOURCES,
    sinks: ARGPARSE_GEN_SINKS,
    sanitizers: ARGPARSE_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
