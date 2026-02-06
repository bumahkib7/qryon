//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_PERSONALITY_DWARF_EH_FIND_EH_ACTION_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYS_PERSONALITY_DWARF_EH_FIND_EH_ACTION_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "std::sys::personality::dwarf::eh::find_eh_action.Argument[0]",
    pattern: SinkKind::FunctionCall(""),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[0] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static STD_SYS_PERSONALITY_DWARF_EH_FIND_EH_ACTION_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_PERSONALITY_DWARF_EH_FIND_EH_ACTION_GEN_IMPORTS: &[&str] =
    &["std::sys::personality::dwarf::eh::find_eh_action"];

pub static STD_SYS_PERSONALITY_DWARF_EH_FIND_EH_ACTION_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "std::sys::personality::dwarf::eh::find_eh_action_generated",
        description: "Generated profile for std::sys::personality::dwarf::eh::find_eh_action from CodeQL/Pysa",
        detect_imports: STD_SYS_PERSONALITY_DWARF_EH_FIND_EH_ACTION_GEN_IMPORTS,
        sources: STD_SYS_PERSONALITY_DWARF_EH_FIND_EH_ACTION_GEN_SOURCES,
        sinks: STD_SYS_PERSONALITY_DWARF_EH_FIND_EH_ACTION_GEN_SINKS,
        sanitizers: STD_SYS_PERSONALITY_DWARF_EH_FIND_EH_ACTION_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
