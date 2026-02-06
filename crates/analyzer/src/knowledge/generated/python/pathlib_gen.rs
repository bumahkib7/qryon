//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PATHLIB_GEN_SOURCES: &[SourceDef] = &[];

static PATHLIB_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "pathlib.Path.symlink_to",
        pattern: SinkKind::FunctionCall("pathlib.Path.symlink_to"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: pathlib.Path.symlink_to (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "pathlib.Path.rglob",
        pattern: SinkKind::FunctionCall("pathlib.Path.rglob"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: pathlib.Path.rglob (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "pathlib.Path.chmod",
        pattern: SinkKind::FunctionCall("pathlib.Path.chmod"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: pathlib.Path.chmod (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "pathlib.Path.lchmod",
        pattern: SinkKind::FunctionCall("pathlib.Path.lchmod"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: pathlib.Path.lchmod (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "pathlib.Path.mkdir",
        pattern: SinkKind::FunctionCall("pathlib.Path.mkdir"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: pathlib.Path.mkdir (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "pathlib.Path.rename",
        pattern: SinkKind::FunctionCall("pathlib.Path.rename"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: pathlib.Path.rename (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "pathlib.Path.replace",
        pattern: SinkKind::FunctionCall("pathlib.Path.replace"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: pathlib.Path.replace (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "pathlib.Path.rmdir",
        pattern: SinkKind::FunctionCall("pathlib.Path.rmdir"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: pathlib.Path.rmdir (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "pathlib.Path.touch",
        pattern: SinkKind::FunctionCall("pathlib.Path.touch"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: pathlib.Path.touch (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "pathlib.Path.unlink",
        pattern: SinkKind::FunctionCall("pathlib.Path.unlink"),
        rule_id: "python/gen-pysa-filesystem_other",
        severity: Severity::Error,
        description: "Pysa sink: pathlib.Path.unlink (kind: FileSystem_Other)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "pathlib.PurePath.__new__",
        pattern: SinkKind::FunctionCall("pathlib.PurePath.__new__"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pathlib.PurePath.__new__ (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pathlib.PurePath.__truediv__",
        pattern: SinkKind::FunctionCall("pathlib.PurePath.__truediv__"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pathlib.PurePath.__truediv__ (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pathlib.PurePath.__rtruediv__",
        pattern: SinkKind::FunctionCall("pathlib.PurePath.__rtruediv__"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pathlib.PurePath.__rtruediv__ (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pathlib.Path.__new__",
        pattern: SinkKind::FunctionCall("pathlib.Path.__new__"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pathlib.Path.__new__ (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pathlib.Path.read_bytes",
        pattern: SinkKind::FunctionCall("pathlib.Path.read_bytes"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pathlib.Path.read_bytes (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pathlib.Path.read_text",
        pattern: SinkKind::FunctionCall("pathlib.Path.read_text"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pathlib.Path.read_text (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pathlib.Path.write_bytes",
        pattern: SinkKind::FunctionCall("pathlib.Path.write_bytes"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pathlib.Path.write_bytes (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pathlib.Path.write_text",
        pattern: SinkKind::FunctionCall("pathlib.Path.write_text"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pathlib.Path.write_text (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
];

static PATHLIB_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PATHLIB_GEN_IMPORTS: &[&str] = &["pathlib"];

pub static PATHLIB_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "pathlib_generated",
    description: "Generated profile for pathlib from CodeQL/Pysa",
    detect_imports: PATHLIB_GEN_IMPORTS,
    sources: PATHLIB_GEN_SOURCES,
    sinks: PATHLIB_GEN_SINKS,
    sanitizers: PATHLIB_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
