//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static IO_FS_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "io/fs.ReadFile",
        pattern: SourceKind::MemberAccess("io/fs.ReadFile"),
        taint_label: "user_input",
        description: "CodeQL source: io/fs..ReadFile (kind: manual)",
    },
    SourceDef {
        name: "io/fs.ReadFileFS.ReadFile",
        pattern: SourceKind::MemberAccess("io/fs.ReadFileFS.ReadFile"),
        taint_label: "user_input",
        description: "CodeQL source: io/fs.ReadFileFS.ReadFile (kind: manual)",
    },
    SourceDef {
        name: "io/fs.FS.Open",
        pattern: SourceKind::MemberAccess("io/fs.FS.Open"),
        taint_label: "user_input",
        description: "CodeQL source: io/fs.FS.Open (kind: manual)",
    },
];

static IO_FS_GEN_SINKS: &[SinkDef] = &[];

static IO_FS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static IO_FS_GEN_IMPORTS: &[&str] = &["io/fs"];

pub static IO_FS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "io_fs_generated",
    description: "Generated profile for io/fs from CodeQL/Pysa",
    detect_imports: IO_FS_GEN_IMPORTS,
    sources: IO_FS_GEN_SOURCES,
    sinks: IO_FS_GEN_SINKS,
    sanitizers: IO_FS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
