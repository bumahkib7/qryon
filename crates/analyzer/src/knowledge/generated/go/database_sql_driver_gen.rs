//! Auto-generated from CodeQL Models-as-Data + Pysa taint stubs
//! Do not edit manually — regenerate with `cargo run -p knowledge-gen`

use crate::knowledge::types::{
    FrameworkProfile, SanitizerDef, SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

static DATABASE_SQL_DRIVER_GEN_SOURCES: &[SourceDef] = &[
    SourceDef {
        name: "database/sql/driver.Queryer.Query",
        pattern: SourceKind::MemberAccess("database/sql/driver.Queryer.Query"),
        taint_label: "user_input",
        description: "CodeQL source: database/sql/driver.Queryer.Query (kind: manual)",
    },
    SourceDef {
        name: "database/sql/driver.QueryerContext.QueryContext",
        pattern: SourceKind::MemberAccess("database/sql/driver.QueryerContext.QueryContext"),
        taint_label: "user_input",
        description: "CodeQL source: database/sql/driver.QueryerContext.QueryContext (kind: manual)",
    },
    SourceDef {
        name: "database/sql/driver.Stmt.Query",
        pattern: SourceKind::MemberAccess("database/sql/driver.Stmt.Query"),
        taint_label: "user_input",
        description: "CodeQL source: database/sql/driver.Stmt.Query (kind: manual)",
    },
    SourceDef {
        name: "database/sql/driver.StmtQueryContext.QueryContext",
        pattern: SourceKind::MemberAccess("database/sql/driver.StmtQueryContext.QueryContext"),
        taint_label: "user_input",
        description: "CodeQL source: database/sql/driver.StmtQueryContext.QueryContext (kind: manual)",
    },
];

static DATABASE_SQL_DRIVER_GEN_SINKS: &[SinkDef] = &[
    SinkDef {
        name: "database/sql/driver.Execer.Exec",
        pattern: SinkKind::FunctionCall("database/sql/driver.Execer.Exec"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: database/sql/driver.Execer.Exec (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "database/sql/driver.ExecerContext.ExecContext",
        pattern: SinkKind::FunctionCall("database/sql/driver.ExecerContext.ExecContext"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: database/sql/driver.ExecerContext.ExecContext (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "database/sql/driver.Conn.Prepare",
        pattern: SinkKind::FunctionCall("database/sql/driver.Conn.Prepare"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: database/sql/driver.Conn.Prepare (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "database/sql/driver.ConnPrepareContext.PrepareContext",
        pattern: SinkKind::FunctionCall("database/sql/driver.ConnPrepareContext.PrepareContext"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: database/sql/driver.ConnPrepareContext.PrepareContext (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "database/sql/driver.Queryer.Query",
        pattern: SinkKind::FunctionCall("database/sql/driver.Queryer.Query"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: database/sql/driver.Queryer.Query (kind: manual)",
        cwe: Some("CWE-74"),
    },
    SinkDef {
        name: "database/sql/driver.QueryerContext.QueryContext",
        pattern: SinkKind::FunctionCall("database/sql/driver.QueryerContext.QueryContext"),
        rule_id: "go/gen-manual",
        severity: Severity::Error,
        description: "CodeQL sink: database/sql/driver.QueryerContext.QueryContext (kind: manual)",
        cwe: Some("CWE-74"),
    },
];

static DATABASE_SQL_DRIVER_GEN_SANITIZERS: &[SanitizerDef] = &[];

static DATABASE_SQL_DRIVER_GEN_IMPORTS: &[&str] = &["database/sql/driver"];

pub static DATABASE_SQL_DRIVER_GEN_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "database_sql_driver_generated",
    description: "Generated profile for database/sql/driver from CodeQL/Pysa",
    detect_imports: DATABASE_SQL_DRIVER_GEN_IMPORTS,
    sources: DATABASE_SQL_DRIVER_GEN_SOURCES,
    sinks: DATABASE_SQL_DRIVER_GEN_SINKS,
    sanitizers: DATABASE_SQL_DRIVER_GEN_SANITIZERS,
    safe_patterns: &[],
    dangerous_patterns: &[],
    resource_types: &[],
};
