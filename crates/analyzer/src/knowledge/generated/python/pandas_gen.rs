//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static PANDAS_GEN_SOURCES: &[SourceDef] = &[];

static PANDAS_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "pandas.core.computation.eval.eval",
        pattern: SinkKind::FunctionCall("pandas.core.computation.eval.eval"),
        rule_id: "python/gen-pysa-remotecodeexecution",
        severity: Severity::Critical,
        description: "Pysa sink: pandas.core.computation.eval.eval (kind: RemoteCodeExecution)",
        cwe: Some("CWE-78"),
    },
    SinkDef {
        name: "pandas.io.sql.read_sql",
        pattern: SinkKind::FunctionCall("pandas.io.sql.read_sql"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: pandas.io.sql.read_sql (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "pandas.io.sql.read_sql_query",
        pattern: SinkKind::FunctionCall("pandas.io.sql.read_sql_query"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: pandas.io.sql.read_sql_query (kind: SQL)",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "pandas.io.spss.read_spss",
        pattern: SinkKind::FunctionCall("pandas.io.spss.read_spss"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pandas.io.spss.read_spss (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pandas.core.generic.NDFrame.to_csv",
        pattern: SinkKind::FunctionCall("pandas.core.generic.NDFrame.to_csv"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pandas.core.generic.NDFrame.to_csv (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pandas.core.generic.NDFrame.to_hdf",
        pattern: SinkKind::FunctionCall("pandas.core.generic.NDFrame.to_hdf"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pandas.core.generic.NDFrame.to_hdf (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pandas.core.generic.NDFrame.to_latex",
        pattern: SinkKind::FunctionCall("pandas.core.generic.NDFrame.to_latex"),
        rule_id: "python/gen-pysa-filesystem_readwrite",
        severity: Severity::Critical,
        description: "Pysa sink: pandas.core.generic.NDFrame.to_latex (kind: FileSystem_ReadWrite)",
        cwe: Some("CWE-22"),
    },
    SinkDef {
        name: "pandas.core.generic.NDFrame.to_sql",
        pattern: SinkKind::FunctionCall("pandas.core.generic.NDFrame.to_sql"),
        rule_id: "python/gen-pysa-sql",
        severity: Severity::Critical,
        description: "Pysa sink: pandas.core.generic.NDFrame.to_sql (kind: SQL)",
        cwe: Some("CWE-89"),
    },
];

static PANDAS_GEN_SANITIZERS: &[SanitizerDef] = &[];

static PANDAS_GEN_IMPORTS: &[&str] = &["pandas"];

pub static PANDAS_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "pandas_generated",
    description: "Generated profile for pandas from CodeQL/Pysa",
    detect_imports: PANDAS_GEN_IMPORTS,
    sources: PANDAS_GEN_SOURCES,
    sinks: PANDAS_GEN_SINKS,
    sanitizers: PANDAS_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
