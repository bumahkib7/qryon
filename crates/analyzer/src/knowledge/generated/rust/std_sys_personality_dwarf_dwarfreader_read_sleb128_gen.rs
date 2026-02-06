//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static STD_SYS_PERSONALITY_DWARF_DWARFREADER_READ_SLEB128_GEN_SOURCES: &[SourceDef] = &[];

static STD_SYS_PERSONALITY_DWARF_DWARFREADER_READ_SLEB128_GEN_SINKS: &[SinkDef] = &[SinkDef {
    name: "<std::sys::personality::dwarf::DwarfReader>::read_sleb128.Argument[self]",
    pattern: SinkKind::FunctionCall("Argument[self]"),
    rule_id: "rust/gen-pointer-access",
    severity: Severity::Error,
    description: "CodeQL sink: Argument[self] (kind: pointer-access)",
    cwe: Some("CWE-74"),
}];

static STD_SYS_PERSONALITY_DWARF_DWARFREADER_READ_SLEB128_GEN_SANITIZERS: &[SanitizerDef] = &[];

static STD_SYS_PERSONALITY_DWARF_DWARFREADER_READ_SLEB128_GEN_IMPORTS: &[&str] =
    &["<std::sys::personality::dwarf::DwarfReader>::read_sleb128"];

pub static STD_SYS_PERSONALITY_DWARF_DWARFREADER_READ_SLEB128_GEN_PROFILE: FrameworkProfile =
    FrameworkProfile {
        name: "<std::sys::personality::dwarf::dwarfreader>::read_sleb128_generated",
        description: "Generated profile for <std::sys::personality::dwarf::DwarfReader>::read_sleb128 from CodeQL/Pysa",
        detect_imports: STD_SYS_PERSONALITY_DWARF_DWARFREADER_READ_SLEB128_GEN_IMPORTS,
        sources: STD_SYS_PERSONALITY_DWARF_DWARFREADER_READ_SLEB128_GEN_SOURCES,
        sinks: STD_SYS_PERSONALITY_DWARF_DWARFREADER_READ_SLEB128_GEN_SINKS,
        sanitizers: STD_SYS_PERSONALITY_DWARF_DWARFREADER_READ_SLEB128_GEN_SANITIZERS,
        safe_patterns: &[],
        dangerous_patterns: &[],
        resource_types: &[],
    };
