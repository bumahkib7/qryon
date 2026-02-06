//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PATH_FILEPATH_GEN_SOURCES: &[SourceDef] = &[];

static PATH_FILEPATH_GEN_SINKS: &[SinkDef] = &[];

static PATH_FILEPATH_GEN_SANITIZERS: &[SanitizerDef] = &[SanitizerDef {
    name: "path/filepath.Clean",
    pattern: SanitizerKind::Function("path/filepath..Clean"),
    sanitizes: "path",
    description: "CodeQL sanitizer: path/filepath..Clean",
}];

static PATH_FILEPATH_GEN_IMPORTS: &[&str] = &["path/filepath"];

pub static PATH_FILEPATH_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "path_filepath_generated",
    description: "Generated profile for path/filepath from CodeQL/Pysa",
    detect_imports: PATH_FILEPATH_GEN_IMPORTS,
    sources: PATH_FILEPATH_GEN_SOURCES,
    sinks: PATH_FILEPATH_GEN_SINKS,
    sanitizers: PATH_FILEPATH_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
