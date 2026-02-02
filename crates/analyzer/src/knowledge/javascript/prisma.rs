//! Prisma and Sequelize ORM security knowledge
//!
//! Defines taint sources, sinks, and sanitizers for database ORMs.
//! Prisma's query builder is safe by default, but raw queries can
//! introduce SQL injection vulnerabilities.
//!
//! NOTE: This module DETECTS security vulnerabilities - it does not contain them.
//! The patterns here are used to identify dangerous code during static analysis.

use crate::knowledge::types::{
    DangerousPattern, FrameworkProfile, PatternKind, ResourceType, SafePattern, SanitizerDef,
    SanitizerKind, SinkDef, SinkKind, SourceDef, SourceKind,
};
use rma_common::Severity;

/// Prisma and database ORM security profile
pub static PRISMA_PROFILE: FrameworkProfile = FrameworkProfile {
    name: "prisma",
    description: "Prisma ORM and database access patterns",
    detect_imports: &[
        "@prisma/client",
        "from '@prisma/client'",
        "from \"@prisma/client\"",
        "PrismaClient",
        "sequelize",
        "from 'sequelize'",
        "from \"sequelize\"",
        "Sequelize",
        "typeorm",
        "from 'typeorm'",
        "knex",
        "from 'knex'",
    ],
    sources: &PRISMA_SOURCES,
    sinks: &PRISMA_SINKS,
    sanitizers: &PRISMA_SANITIZERS,
    safe_patterns: &PRISMA_SAFE_PATTERNS,
    dangerous_patterns: &PRISMA_DANGEROUS_PATTERNS,
    resource_types: &PRISMA_RESOURCES,
};

/// Taint sources - database query results and user input
static PRISMA_SOURCES: [SourceDef; 8] = [
    // Prisma query results
    SourceDef {
        name: "prisma.findMany",
        pattern: SourceKind::MethodOnType {
            type_pattern: "PrismaClient",
            method: "findMany",
        },
        taint_label: "database",
        description: "Database query result - may contain sensitive data",
    },
    SourceDef {
        name: "prisma.findUnique",
        pattern: SourceKind::MethodOnType {
            type_pattern: "PrismaClient",
            method: "findUnique",
        },
        taint_label: "database",
        description: "Database query result - may contain sensitive data",
    },
    SourceDef {
        name: "prisma.findFirst",
        pattern: SourceKind::MethodOnType {
            type_pattern: "PrismaClient",
            method: "findFirst",
        },
        taint_label: "database",
        description: "Database query result - may contain sensitive data",
    },
    // Sequelize query results
    SourceDef {
        name: "sequelize.query",
        pattern: SourceKind::FunctionCall("sequelize.query"),
        taint_label: "database",
        description: "Raw SQL query result - may contain sensitive data",
    },
    SourceDef {
        name: "Model.findAll",
        pattern: SourceKind::FunctionCall("findAll"),
        taint_label: "database",
        description: "Sequelize query result",
    },
    SourceDef {
        name: "Model.findOne",
        pattern: SourceKind::FunctionCall("findOne"),
        taint_label: "database",
        description: "Sequelize query result",
    },
    // TypeORM
    SourceDef {
        name: "repository.find",
        pattern: SourceKind::MethodOnType {
            type_pattern: "Repository",
            method: "find",
        },
        taint_label: "database",
        description: "TypeORM query result",
    },
    // Knex
    SourceDef {
        name: "knex.select",
        pattern: SourceKind::FunctionCall("select"),
        taint_label: "database",
        description: "Knex query result",
    },
];

/// Dangerous sinks - raw SQL execution
static PRISMA_SINKS: [SinkDef; 12] = [
    // Prisma raw queries - DETECTION patterns
    SinkDef {
        name: "$queryRawUnsafe",
        pattern: SinkKind::MethodCall("$queryRawUnsafe"),
        rule_id: "prisma/sql-injection",
        severity: Severity::Critical,
        description: "Detects unsafe raw SQL query - high injection risk",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "$executeRawUnsafe",
        pattern: SinkKind::MethodCall("$executeRawUnsafe"),
        rule_id: "prisma/sql-injection",
        severity: Severity::Critical,
        description: "Detects unsafe raw SQL execution - high injection risk",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "$queryRaw_string",
        pattern: SinkKind::MethodCall("$queryRaw"),
        rule_id: "prisma/raw-query",
        severity: Severity::Warning,
        description: "Detects raw SQL query - use tagged template for safety",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "$executeRaw",
        pattern: SinkKind::MethodCall("$executeRaw"),
        rule_id: "prisma/raw-execute",
        severity: Severity::Warning,
        description: "Detects raw SQL execution - use tagged template for safety",
        cwe: Some("CWE-89"),
    },
    // Sequelize raw queries
    SinkDef {
        name: "sequelize.query",
        pattern: SinkKind::FunctionCall("sequelize.query"),
        rule_id: "sequelize/sql-injection",
        severity: Severity::Error,
        description: "Detects raw SQL query - use parameterized query",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "Sequelize.literal",
        pattern: SinkKind::FunctionCall("Sequelize.literal"),
        rule_id: "sequelize/sql-injection",
        severity: Severity::Critical,
        description: "Detects SQL literal - dangerous with user input",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "Op.col",
        pattern: SinkKind::FunctionCall("Op.col"),
        rule_id: "sequelize/sql-injection",
        severity: Severity::Warning,
        description: "Detects column reference - validate column name",
        cwe: Some("CWE-89"),
    },
    // TypeORM raw queries
    SinkDef {
        name: "createQueryBuilder.where_raw",
        pattern: SinkKind::MethodCall("where"),
        rule_id: "typeorm/sql-injection",
        severity: Severity::Warning,
        description: "Detects where clause - use parameterized queries",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "manager.query",
        pattern: SinkKind::MethodCall("query"),
        rule_id: "typeorm/raw-query",
        severity: Severity::Error,
        description: "Detects raw SQL query - use parameterized version",
        cwe: Some("CWE-89"),
    },
    // Knex raw queries
    SinkDef {
        name: "knex.raw",
        pattern: SinkKind::FunctionCall("raw"),
        rule_id: "knex/sql-injection",
        severity: Severity::Error,
        description: "Detects raw SQL - use parameter bindings",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "knex.whereRaw",
        pattern: SinkKind::MethodCall("whereRaw"),
        rule_id: "knex/sql-injection",
        severity: Severity::Error,
        description: "Detects raw WHERE clause - use parameter bindings",
        cwe: Some("CWE-89"),
    },
    SinkDef {
        name: "knex.orderByRaw",
        pattern: SinkKind::MethodCall("orderByRaw"),
        rule_id: "knex/sql-injection",
        severity: Severity::Warning,
        description: "Detects raw ORDER BY - validate column names",
        cwe: Some("CWE-89"),
    },
];

/// Sanitizers for database operations
static PRISMA_SANITIZERS: [SanitizerDef; 6] = [
    SanitizerDef {
        name: "Prisma.sql",
        pattern: SanitizerKind::Function("Prisma.sql"),
        sanitizes: "sql",
        description: "Prisma tagged template for parameterized queries",
    },
    SanitizerDef {
        name: "Prisma.join",
        pattern: SanitizerKind::Function("Prisma.join"),
        sanitizes: "sql",
        description: "Prisma join helper for safe array parameters",
    },
    SanitizerDef {
        name: "sequelize_replacements",
        pattern: SanitizerKind::Function("{ replacements }"),
        sanitizes: "sql",
        description: "Sequelize parameterized replacements",
    },
    SanitizerDef {
        name: "parseInt",
        pattern: SanitizerKind::Function("parseInt"),
        sanitizes: "numeric",
        description: "Convert to integer - removes non-numeric content",
    },
    SanitizerDef {
        name: "Number",
        pattern: SanitizerKind::Function("Number"),
        sanitizes: "numeric",
        description: "Convert to number",
    },
    SanitizerDef {
        name: "validator.isUUID",
        pattern: SanitizerKind::Function("isUUID"),
        sanitizes: "uuid",
        description: "Validates UUID format",
    },
];

/// Safe patterns - inherently safe database access
static PRISMA_SAFE_PATTERNS: [SafePattern; 8] = [
    SafePattern {
        name: "prisma_query_builder",
        pattern: "prisma.model.findMany({ where: ... })",
        reason: "Prisma query builder uses parameterized queries internally",
    },
    SafePattern {
        name: "prisma_sql_tagged",
        pattern: "prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`",
        reason: "Tagged template literal creates parameterized query",
    },
    SafePattern {
        name: "prisma_sql_helper",
        pattern: "Prisma.sql`SELECT * FROM users WHERE id = ${id}`",
        reason: "Prisma.sql creates safe parameterized query",
    },
    SafePattern {
        name: "sequelize_model_query",
        pattern: "User.findAll({ where: { id: userId } })",
        reason: "Sequelize query builder uses parameterized queries",
    },
    SafePattern {
        name: "sequelize_replacements",
        pattern: "sequelize.query('SELECT * FROM users WHERE id = ?', { replacements: [id] })",
        reason: "Replacements create parameterized query",
    },
    SafePattern {
        name: "typeorm_query_builder",
        pattern: "createQueryBuilder().where('user.id = :id', { id })",
        reason: "TypeORM parameter binding is safe",
    },
    SafePattern {
        name: "knex_query_builder",
        pattern: "knex('users').where({ id })",
        reason: "Knex query builder uses parameterized queries",
    },
    SafePattern {
        name: "knex_bindings",
        pattern: "knex.raw('id = ?', [userId])",
        reason: "Knex raw with bindings is parameterized",
    },
];

/// Dangerous patterns in database access
static PRISMA_DANGEROUS_PATTERNS: [DangerousPattern; 10] = [
    DangerousPattern {
        name: "queryRawUnsafe_user_input",
        pattern: PatternKind::Construct("$queryRawUnsafe(userInput)"),
        rule_id: "prisma/sql-injection",
        severity: Severity::Critical,
        description: "Detects $queryRawUnsafe with user input - SQL injection",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "queryRaw_template_interpolation",
        pattern: PatternKind::Regex(r#"\$queryRaw\s*\(\s*`[^`]*\$\{"#),
        rule_id: "prisma/sql-injection",
        severity: Severity::Critical,
        description: "Detects $queryRaw with string interpolation - use Prisma.sql",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "queryRaw_string_concat",
        pattern: PatternKind::Regex(r#"\$queryRaw\s*\([^)]*\+[^)]*\)"#),
        rule_id: "prisma/sql-injection",
        severity: Severity::Critical,
        description: "Detects $queryRaw with string concatenation - SQL injection",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "sequelize_literal_user",
        pattern: PatternKind::Construct("Sequelize.literal(userInput)"),
        rule_id: "sequelize/sql-injection",
        severity: Severity::Critical,
        description: "Detects Sequelize.literal with user input - SQL injection",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "sequelize_query_concat",
        pattern: PatternKind::Regex(r#"sequelize\.query\s*\([^)]*\+[^)]*\)"#),
        rule_id: "sequelize/sql-injection",
        severity: Severity::Critical,
        description: "Detects sequelize.query with concatenation - use replacements",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "typeorm_raw_where",
        pattern: PatternKind::Construct("createQueryBuilder().where(`field = ${value}`)"),
        rule_id: "typeorm/sql-injection",
        severity: Severity::Critical,
        description: "Detects raw interpolation in where - use parameter binding",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "knex_raw_no_bindings",
        pattern: PatternKind::Construct("knex.raw(`SELECT * FROM ${table}`)"),
        rule_id: "knex/sql-injection",
        severity: Severity::Critical,
        description: "Detects knex.raw without bindings - SQL injection",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "dynamic_table_name",
        pattern: PatternKind::Construct("FROM ${tableName}"),
        rule_id: "sql/dynamic-table",
        severity: Severity::Error,
        description: "Detects dynamic table name - whitelist allowed tables",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "dynamic_column_name",
        pattern: PatternKind::Construct("ORDER BY ${column}"),
        rule_id: "sql/dynamic-column",
        severity: Severity::Warning,
        description: "Detects dynamic column in ORDER BY - whitelist allowed columns",
        cwe: Some("CWE-89"),
    },
    DangerousPattern {
        name: "exposed_connection_string",
        pattern: PatternKind::Regex(
            r#"(DATABASE_URL|DB_CONNECTION)\s*=\s*['"](postgres|mysql|mongodb)://"#,
        ),
        rule_id: "database/exposed-credentials",
        severity: Severity::Critical,
        description: "Detects hardcoded database connection string",
        cwe: Some("CWE-798"),
    },
];

/// Database-specific resources
static PRISMA_RESOURCES: [ResourceType; 4] = [
    ResourceType {
        name: "PrismaClient",
        acquire_pattern: "new PrismaClient()",
        release_pattern: "prisma.$disconnect()",
        leak_consequence: "Connection pool exhaustion in serverless environments",
    },
    ResourceType {
        name: "SequelizeConnection",
        acquire_pattern: "new Sequelize()",
        release_pattern: "sequelize.close()",
        leak_consequence: "Database connection leak",
    },
    ResourceType {
        name: "TypeORMConnection",
        acquire_pattern: "createConnection()",
        release_pattern: "connection.close()",
        leak_consequence: "Database connection leak",
    },
    ResourceType {
        name: "KnexConnection",
        acquire_pattern: "knex(config)",
        release_pattern: "knex.destroy()",
        leak_consequence: "Connection pool exhaustion",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_detection() {
        assert!(PRISMA_PROFILE.is_active("import { PrismaClient } from '@prisma/client';"));
        assert!(PRISMA_PROFILE.is_active("import Sequelize from 'sequelize';"));
        assert!(PRISMA_PROFILE.is_active("import { createConnection } from 'typeorm';"));
        assert!(PRISMA_PROFILE.is_active("import knex from 'knex';"));
        assert!(!PRISMA_PROFILE.is_active("import mongoose from 'mongoose';"));
    }

    #[test]
    fn test_sources() {
        assert!(!PRISMA_SOURCES.is_empty());
        assert!(PRISMA_SOURCES.iter().any(|s| s.name == "prisma.findMany"));
    }

    #[test]
    fn test_sinks() {
        assert!(!PRISMA_SINKS.is_empty());
        assert!(PRISMA_SINKS.iter().any(|s| s.name == "$queryRawUnsafe"));
        assert!(PRISMA_SINKS.iter().any(|s| s.name == "sequelize.query"));
    }

    #[test]
    fn test_safe_patterns() {
        assert!(!PRISMA_SAFE_PATTERNS.is_empty());
        assert!(
            PRISMA_SAFE_PATTERNS
                .iter()
                .any(|s| s.name == "prisma_sql_tagged")
        );
    }
}
