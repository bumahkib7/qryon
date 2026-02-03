//! RMA Rule Engine - Semgrep-compatible rule loader and matcher
//!
//! This crate provides:
//! - YAML rule parsing (Semgrep format)
//! - Pattern matching engine
//! - Rule registry and loading from directories
//!
//! # Rule Format
//!
//! Rules are defined in YAML files following the Semgrep format:
//!
//! ```yaml
//! rules:
//!   - id: sql-injection
//!     pattern: $DB.query($USER_INPUT)
//!     message: Potential SQL injection
//!     severity: ERROR
//!     languages: [python, javascript]
//!     metadata:
//!       category: security
//!       cwe: "CWE-89"
//! ```

pub mod embedded;
mod format;
mod loader;
mod matcher;
mod pattern;
mod registry;
mod translator;

pub use embedded::{
    embedded_rule_count, embedded_stats, get_literal_triggers, get_match_strategy,
    load_embedded_rules, load_embedded_ruleset, load_rules_for_language, CompiledRule,
    CompiledRuleSet, EmbeddedStats, MatchStrategy,
};
pub use format::*;
pub use loader::*;
pub use matcher::*;
pub use pattern::*;
pub use registry::*;
pub use translator::*;

use thiserror::Error;

/// Rule engine errors
#[derive(Error, Debug)]
pub enum RuleError {
    #[error("Failed to parse rule file: {0}")]
    ParseError(String),

    #[error("Invalid rule format: {0}")]
    FormatError(String),

    #[error("Pattern compilation failed: {0}")]
    PatternError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
}

pub type Result<T> = std::result::Result<T, RuleError>;
