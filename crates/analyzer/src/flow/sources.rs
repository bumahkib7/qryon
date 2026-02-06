//! Taint source, sink, and sanitizer configuration
//!
//! Defines what counts as tainted input, what sanitizes it, and what sinks are dangerous.
//! Integrates with the framework knowledge base for production-level analysis.

use crate::knowledge::MergedKnowledge;
use rma_common::Language;

/// Configuration for taint analysis
///
/// This struct is now a wrapper that integrates with MergedKnowledge
/// while maintaining backwards compatibility with the legacy API.
#[derive(Debug, Clone)]
pub struct TaintConfig {
    /// Sources of tainted data
    pub sources: Vec<TaintSource>,
    /// Functions/methods that sanitize tainted data
    pub sanitizers: Vec<String>,
    /// Dangerous sinks where tainted data should not flow
    pub sinks: Vec<TaintSink>,
    /// Cached source function patterns for O(1) lookup
    source_function_cache: Vec<String>,
    /// Cached source member patterns for O(1) lookup
    source_member_cache: Vec<String>,
}

/// A source of potentially tainted data
#[derive(Debug, Clone)]
pub struct TaintSource {
    /// Pattern to match
    pub pattern: SourcePattern,
    /// Label for this source type
    pub label: String,
}

/// Pattern for matching taint sources
#[derive(Debug, Clone)]
pub enum SourcePattern {
    /// Member access like req.query, req.body
    MemberAccess(String),
    /// Function call like getElementById, querySelector
    FunctionCall(String),
    /// Any function parameter (conservative)
    Parameter,
}

impl SourcePattern {
    /// Get the function name if this is a FunctionCall pattern
    pub fn as_function_name(&self) -> Option<String> {
        match self {
            SourcePattern::FunctionCall(name) => Some(name.clone()),
            _ => None,
        }
    }

    /// Get the member path if this is a MemberAccess pattern
    pub fn as_member_path(&self) -> Option<&str> {
        match self {
            SourcePattern::MemberAccess(path) => Some(path),
            _ => None,
        }
    }
}

/// A dangerous sink
#[derive(Debug, Clone)]
pub struct TaintSink {
    /// Rule ID to associate with this sink
    pub rule_id: String,
    /// Pattern to match
    pub pattern: SinkPattern,
}

/// Pattern for matching sinks
#[derive(Debug, Clone)]
pub enum SinkPattern {
    /// Property assignment like innerHTML, outerHTML
    PropertyAssignment(String),
    /// Function call like eval, exec
    FunctionCall(String),
    /// Template literal with tainted variable
    TemplateInsertion,
}

impl SinkPattern {
    /// Get the function name if this is a FunctionCall pattern
    pub fn as_function_name(&self) -> Option<String> {
        match self {
            SinkPattern::FunctionCall(name) => Some(name.clone()),
            _ => None,
        }
    }

    /// Get the property name if this is a PropertyAssignment pattern
    pub fn as_property_name(&self) -> Option<&str> {
        match self {
            SinkPattern::PropertyAssignment(name) => Some(name),
            _ => None,
        }
    }
}

impl TaintConfig {
    /// Get taint configuration for a language
    pub fn for_language(language: Language) -> Self {
        match language {
            Language::JavaScript | Language::TypeScript => Self::javascript(),
            Language::Rust => Self::rust(),
            Language::Go => Self::go(),
            Language::Python => Self::python(),
            Language::Php => Self::php(),
            Language::CSharp => Self::csharp(),
            Language::Kotlin | Language::Scala => Self::java_family(),
            Language::Swift => Self::swift(),
            Language::Bash => Self::bash(),
            Language::Elixir => Self::elixir(),
            Language::Solidity => Self::solidity(),
            _ => Self::empty(),
        }
    }

    /// Get taint configuration for a language with merged knowledge
    ///
    /// This is the preferred method for production use. It combines
    /// the base language configuration with framework-specific knowledge.
    pub fn for_language_with_knowledge(language: Language, knowledge: &MergedKnowledge) -> Self {
        let mut config = Self::for_language(language);

        // Extend sources from knowledge
        for pattern in knowledge.all_source_patterns() {
            // Check if it looks like a member access or function call
            if pattern.contains('.') {
                config.source_member_cache.push(pattern.to_string());
            } else {
                config.source_function_cache.push(pattern.to_string());
            }
        }

        // Mark parameters as sources if knowledge says so
        if knowledge.parameters_are_sources() {
            let has_param_source = config
                .sources
                .iter()
                .any(|s| matches!(s.pattern, SourcePattern::Parameter));
            if !has_param_source {
                config.sources.push(TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".to_string(),
                });
            }
        }

        config
    }

    /// Empty configuration
    pub fn empty() -> Self {
        Self {
            sources: Vec::new(),
            sanitizers: Vec::new(),
            sinks: Vec::new(),
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    /// Check if a function call is a taint source
    pub fn is_source_function(&self, func_name: &str) -> bool {
        // Check cached patterns first (from knowledge)
        for pattern in &self.source_function_cache {
            if func_name == pattern || func_name.ends_with(pattern) || func_name.contains(pattern) {
                return true;
            }
        }

        // Check base sources
        self.sources.iter().any(|s| match &s.pattern {
            SourcePattern::FunctionCall(pattern) => {
                func_name == pattern || func_name.ends_with(&format!(".{}", pattern))
            }
            _ => false,
        })
    }

    /// Check if a member access is a taint source
    pub fn is_source_member(&self, member_path: &str) -> bool {
        // Check cached patterns first (from knowledge)
        for pattern in &self.source_member_cache {
            if member_path == pattern
                || member_path.contains(pattern)
                || member_path.ends_with(pattern)
            {
                return true;
            }
        }

        // Check base sources
        self.sources.iter().any(|s| match &s.pattern {
            SourcePattern::MemberAccess(pattern) => {
                member_path == pattern
                    || member_path.contains(pattern)
                    || member_path.ends_with(pattern)
            }
            _ => false,
        })
    }

    /// Check if a function is a sanitizer
    pub fn is_sanitizer(&self, func_name: &str) -> bool {
        self.sanitizers.iter().any(|s| {
            func_name == s || func_name.ends_with(&format!(".{}", s)) || func_name.contains(s)
        })
    }

    /// Check if a property assignment is a sink
    pub fn is_sink_property(&self, prop_name: &str) -> bool {
        self.sinks.iter().any(|s| match &s.pattern {
            SinkPattern::PropertyAssignment(pattern) => prop_name == pattern,
            _ => false,
        })
    }

    /// Check if a function call is a sink
    pub fn is_sink_function(&self, func_name: &str) -> bool {
        self.sinks.iter().any(|s| match &s.pattern {
            SinkPattern::FunctionCall(pattern) => {
                func_name == pattern || func_name.ends_with(&format!(".{}", pattern))
            }
            _ => false,
        })
    }

    /// Check if a function call is an SQL sink
    pub fn is_sql_sink(&self, func_name: &str) -> bool {
        self.sinks.iter().any(|s| match &s.pattern {
            SinkPattern::FunctionCall(pattern) => {
                s.rule_id.contains("sql-injection")
                    && (func_name == pattern
                        || func_name.ends_with(&format!(".{}", pattern))
                        || func_name.contains(pattern))
            }
            _ => false,
        })
    }

    /// Get all SQL sink patterns for matching
    pub fn sql_sink_patterns(&self) -> Vec<&str> {
        self.sinks
            .iter()
            .filter(|s| s.rule_id.contains("sql-injection"))
            .filter_map(|s| match &s.pattern {
                SinkPattern::FunctionCall(pattern) => Some(pattern.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Check if a query string uses parameterized placeholders (sanitized for SQL)
    ///
    /// Recognizes common placeholder patterns:
    /// - ? (JDBC, MySQL, SQLite)
    /// - $1, $2, ... (PostgreSQL)
    /// - :name, :param (Named parameters - Python, SQLAlchemy, Oracle)
    /// - @param (SQL Server, ADO.NET)
    /// - %s (Python DB-API with params tuple)
    pub fn is_parameterized_query(query: &str) -> bool {
        // Check for common parameterized query patterns
        // These indicate safe usage with bound parameters

        // ? placeholders (JDBC, MySQL, SQLite)
        if query.contains('?') {
            return true;
        }

        // $1, $2, ... PostgreSQL positional placeholders
        if query.contains("$1") || query.contains("$2") {
            return true;
        }

        // :name or :param named placeholders (SQLAlchemy, Oracle)
        // Match :word patterns that look like bind variables
        let has_named_param = query.chars().enumerate().any(|(i, c)| {
            if c == ':' && i + 1 < query.len() {
                let next_char = query.chars().nth(i + 1).unwrap_or(' ');
                // Check it's :name not ::type_cast
                next_char.is_alphabetic() && (i == 0 || query.chars().nth(i - 1) != Some(':'))
            } else {
                false
            }
        });
        if has_named_param {
            return true;
        }

        // @param (SQL Server, ADO.NET)
        if query.contains('@') {
            let has_at_param = query.chars().enumerate().any(|(i, c)| {
                if c == '@' && i + 1 < query.len() {
                    let next_char = query.chars().nth(i + 1).unwrap_or(' ');
                    next_char.is_alphabetic()
                } else {
                    false
                }
            });
            if has_at_param {
                return true;
            }
        }

        false
    }

    /// Check if a function call looks like a safe prepared statement usage
    pub fn is_prepared_statement_call(func_name: &str) -> bool {
        let safe_patterns = [
            "prepare",
            "prepareStatement",
            "preparedStatement",
            "PreparedStatement",
            "createStatement",
            "NamedParameterJdbcTemplate",
            "SqlParameterSource",
            "text", // Prisma/Knex text() for parameterized queries
        ];
        safe_patterns.iter().any(|p| func_name.contains(p))
    }

    fn javascript() -> Self {
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::MemberAccess("req.query".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("req.body".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("req.params".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("request.query".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("request.body".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("document.location".into()),
                    label: "url_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("window.location".into()),
                    label: "url_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("location.href".into()),
                    label: "url_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("location.search".into()),
                    label: "url_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("location.hash".into()),
                    label: "url_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("document.URL".into()),
                    label: "url_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("document.referrer".into()),
                    label: "url_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("document.cookie".into()),
                    label: "cookie_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("getElementById".into()),
                    label: "dom_read".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("querySelector".into()),
                    label: "dom_read".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("querySelectorAll".into()),
                    label: "dom_read".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("getElementsByClassName".into()),
                    label: "dom_read".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("getElementsByName".into()),
                    label: "dom_read".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("prompt".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("URLSearchParams".into()),
                    label: "url_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("localStorage".into()),
                    label: "storage".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("sessionStorage".into()),
                    label: "storage".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec![
                "DOMPurify.sanitize".into(),
                "sanitize".into(),
                "encodeURIComponent".into(),
                "encodeURI".into(),
                "escape".into(),
                "textContent".into(),
                "createTextNode".into(),
                "sanitizeHtml".into(),
                "xss".into(),
                "validator.escape".into(),
                "he.encode".into(),
                "React.createElement".into(),
            ],
            sinks: vec![
                TaintSink {
                    rule_id: "js/innerhtml-xss".into(),
                    pattern: SinkPattern::PropertyAssignment("innerHTML".into()),
                },
                TaintSink {
                    rule_id: "js/innerhtml-xss".into(),
                    pattern: SinkPattern::PropertyAssignment("outerHTML".into()),
                },
                TaintSink {
                    rule_id: "js/dom-write".into(),
                    pattern: SinkPattern::FunctionCall("write".into()),
                },
                TaintSink {
                    rule_id: "js/dom-write".into(),
                    pattern: SinkPattern::FunctionCall("writeln".into()),
                },
                TaintSink {
                    rule_id: "js/innerhtml-xss".into(),
                    pattern: SinkPattern::FunctionCall("insertAdjacentHTML".into()),
                },
                TaintSink {
                    rule_id: "js/dynamic-code-execution".into(),
                    pattern: SinkPattern::FunctionCall("eval".into()),
                },
                TaintSink {
                    rule_id: "js/dynamic-code-execution".into(),
                    pattern: SinkPattern::FunctionCall("Function".into()),
                },
                TaintSink {
                    rule_id: "js/timer-string-eval".into(),
                    pattern: SinkPattern::FunctionCall("setTimeout".into()),
                },
                TaintSink {
                    rule_id: "js/timer-string-eval".into(),
                    pattern: SinkPattern::FunctionCall("setInterval".into()),
                },
                TaintSink {
                    rule_id: "js/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("exec".into()),
                },
                TaintSink {
                    rule_id: "js/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("execSync".into()),
                },
                TaintSink {
                    rule_id: "js/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("spawn".into()),
                },
                // SQL injection sinks for JavaScript
                TaintSink {
                    rule_id: "js/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("query".into()),
                },
                TaintSink {
                    rule_id: "js/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("execute".into()),
                },
                TaintSink {
                    rule_id: "js/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("db.query".into()),
                },
                TaintSink {
                    rule_id: "js/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("mysql.query".into()),
                },
                TaintSink {
                    rule_id: "js/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("pg.query".into()),
                },
                TaintSink {
                    rule_id: "js/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("connection.query".into()),
                },
                TaintSink {
                    rule_id: "js/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("pool.query".into()),
                },
                TaintSink {
                    rule_id: "js/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("$queryRaw".into()),
                },
                TaintSink {
                    rule_id: "js/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("$executeRaw".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    fn rust() -> Self {
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::FunctionCall("std::env::var".into()),
                    label: "env_var".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("env::var".into()),
                    label: "env_var".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("std::io::stdin".into()),
                    label: "stdin".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("std::fs::read_to_string".into()),
                    label: "file_read".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("fs::read_to_string".into()),
                    label: "file_read".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec!["shell_escape".into(), "escape".into(), "sanitize".into()],
            sinks: vec![
                TaintSink {
                    rule_id: "rust/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("Command::new".into()),
                },
                TaintSink {
                    rule_id: "rust/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("execute".into()),
                },
                TaintSink {
                    rule_id: "rust/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("query".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    fn go() -> Self {
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::MemberAccess("r.URL.Query".into()),
                    label: "url_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("r.FormValue".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("r.Body".into()),
                    label: "request_body".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("os.Getenv".into()),
                    label: "env_var".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("ioutil.ReadAll".into()),
                    label: "io_read".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec![
                "html.EscapeString".into(),
                "url.QueryEscape".into(),
                "template.HTMLEscapeString".into(),
            ],
            sinks: vec![
                TaintSink {
                    rule_id: "go/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("db.Query".into()),
                },
                TaintSink {
                    rule_id: "go/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("db.Exec".into()),
                },
                TaintSink {
                    rule_id: "go/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("db.QueryRow".into()),
                },
                TaintSink {
                    rule_id: "go/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("db.QueryContext".into()),
                },
                TaintSink {
                    rule_id: "go/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("db.ExecContext".into()),
                },
                TaintSink {
                    rule_id: "go/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("tx.Query".into()),
                },
                TaintSink {
                    rule_id: "go/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("tx.Exec".into()),
                },
                TaintSink {
                    rule_id: "go/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("exec.Command".into()),
                },
                TaintSink {
                    rule_id: "go/xss".into(),
                    pattern: SinkPattern::FunctionCall("template.HTML".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    fn python() -> Self {
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::MemberAccess("request.args".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("request.form".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("request.data".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("request.json".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("input".into()),
                    label: "stdin".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("sys.argv".into()),
                    label: "cli_args".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("os.environ".into()),
                    label: "env_var".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("os.getenv".into()),
                    label: "env_var".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec![
                "escape".into(),
                "html.escape".into(),
                "markupsafe.escape".into(),
                "bleach.clean".into(),
                "shlex.quote".into(),
            ],
            sinks: vec![
                TaintSink {
                    rule_id: "python/code-injection".into(),
                    pattern: SinkPattern::FunctionCall("eval".into()),
                },
                TaintSink {
                    rule_id: "python/code-injection".into(),
                    pattern: SinkPattern::FunctionCall("exec".into()),
                },
                TaintSink {
                    rule_id: "python/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("os_system".into()),
                },
                TaintSink {
                    rule_id: "python/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("subprocess.call".into()),
                },
                TaintSink {
                    rule_id: "python/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("subprocess.run".into()),
                },
                // SQL injection sinks for Python
                TaintSink {
                    rule_id: "python/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("cursor.execute".into()),
                },
                TaintSink {
                    rule_id: "python/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("cursor.executemany".into()),
                },
                TaintSink {
                    rule_id: "python/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("db.execute".into()),
                },
                TaintSink {
                    rule_id: "python/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("connection.execute".into()),
                },
                TaintSink {
                    rule_id: "python/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("engine.execute".into()),
                },
                TaintSink {
                    rule_id: "python/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("session.execute".into()),
                },
                TaintSink {
                    rule_id: "python/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("raw".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    fn php() -> Self {
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::MemberAccess("$_GET".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("$_POST".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("$_REQUEST".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("$_COOKIE".into()),
                    label: "cookie_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("$_SERVER".into()),
                    label: "server_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("$_FILES".into()),
                    label: "file_upload".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("file_get_contents".into()),
                    label: "file_read".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec![
                "htmlspecialchars".into(),
                "htmlentities".into(),
                "strip_tags".into(),
                "addslashes".into(),
                "mysqli_real_escape_string".into(),
                "intval".into(),
                "floatval".into(),
            ],
            sinks: vec![
                TaintSink {
                    rule_id: "php/code-injection".into(),
                    pattern: SinkPattern::FunctionCall("eval".into()),
                },
                TaintSink {
                    rule_id: "php/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("exec".into()),
                },
                TaintSink {
                    rule_id: "php/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("system".into()),
                },
                TaintSink {
                    rule_id: "php/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("shell_exec".into()),
                },
                TaintSink {
                    rule_id: "php/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("passthru".into()),
                },
                TaintSink {
                    rule_id: "php/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("popen".into()),
                },
                TaintSink {
                    rule_id: "php/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("mysqli_query".into()),
                },
                TaintSink {
                    rule_id: "php/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("pg_query".into()),
                },
                TaintSink {
                    rule_id: "php/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("query".into()),
                },
                TaintSink {
                    rule_id: "php/xss".into(),
                    pattern: SinkPattern::FunctionCall("echo".into()),
                },
                TaintSink {
                    rule_id: "php/file-inclusion".into(),
                    pattern: SinkPattern::FunctionCall("include".into()),
                },
                TaintSink {
                    rule_id: "php/file-inclusion".into(),
                    pattern: SinkPattern::FunctionCall("require".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    fn csharp() -> Self {
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::MemberAccess("Request.QueryString".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("Request.Form".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("Request.Cookies".into()),
                    label: "cookie_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("Request.Body".into()),
                    label: "request_body".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("HttpContext.Request".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec![
                "HtmlEncoder.Encode".into(),
                "HttpUtility.HtmlEncode".into(),
                "AntiXssEncoder.HtmlEncode".into(),
                "WebUtility.HtmlEncode".into(),
            ],
            sinks: vec![
                TaintSink {
                    rule_id: "csharp/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("Process.Start".into()),
                },
                TaintSink {
                    rule_id: "csharp/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("ExecuteReader".into()),
                },
                TaintSink {
                    rule_id: "csharp/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("ExecuteNonQuery".into()),
                },
                TaintSink {
                    rule_id: "csharp/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("ExecuteScalar".into()),
                },
                TaintSink {
                    rule_id: "csharp/xss".into(),
                    pattern: SinkPattern::FunctionCall("Response.Write".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    fn java_family() -> Self {
        // Shared config for Kotlin and Scala (JVM languages close to Java)
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::FunctionCall("getParameter".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("getHeader".into()),
                    label: "header_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("request.body".into()),
                    label: "request_body".into(),
                },
                TaintSource {
                    pattern: SourcePattern::FunctionCall("readLine".into()),
                    label: "stdin".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec!["escapeHtml".into(), "encode".into(), "sanitize".into()],
            sinks: vec![
                TaintSink {
                    rule_id: "jvm/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("executeQuery".into()),
                },
                TaintSink {
                    rule_id: "jvm/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("executeUpdate".into()),
                },
                TaintSink {
                    rule_id: "jvm/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("exec".into()),
                },
                TaintSink {
                    rule_id: "jvm/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("ProcessBuilder".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    fn swift() -> Self {
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::FunctionCall("URLRequest".into()),
                    label: "url_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("UserDefaults".into()),
                    label: "storage".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("UIPasteboard".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec!["addingPercentEncoding".into(), "htmlEscape".into()],
            sinks: vec![
                TaintSink {
                    rule_id: "swift/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("Process".into()),
                },
                TaintSink {
                    rule_id: "swift/code-injection".into(),
                    pattern: SinkPattern::FunctionCall("evaluateJavaScript".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    fn bash() -> Self {
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::FunctionCall("read".into()),
                    label: "stdin".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("QUERY_STRING".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec![],
            sinks: vec![
                TaintSink {
                    rule_id: "bash/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("eval".into()),
                },
                TaintSink {
                    rule_id: "bash/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("exec".into()),
                },
                TaintSink {
                    rule_id: "bash/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("source".into()),
                },
                TaintSink {
                    rule_id: "bash/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("curl".into()),
                },
                TaintSink {
                    rule_id: "bash/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("wget".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    fn elixir() -> Self {
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::MemberAccess("conn.params".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("conn.query_params".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("conn.body_params".into()),
                    label: "user_input".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec!["html_escape".into(), "safe_to_string".into()],
            sinks: vec![
                TaintSink {
                    rule_id: "elixir/sql-injection".into(),
                    pattern: SinkPattern::FunctionCall("query".into()),
                },
                TaintSink {
                    rule_id: "elixir/command-injection".into(),
                    pattern: SinkPattern::FunctionCall("cmd".into()),
                },
                TaintSink {
                    rule_id: "elixir/code-injection".into(),
                    pattern: SinkPattern::FunctionCall("eval_string".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }

    fn solidity() -> Self {
        Self {
            sources: vec![
                TaintSource {
                    pattern: SourcePattern::MemberAccess("msg.sender".into()),
                    label: "caller".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("msg.value".into()),
                    label: "value".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("msg.data".into()),
                    label: "calldata".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("tx.origin".into()),
                    label: "origin".into(),
                },
                TaintSource {
                    pattern: SourcePattern::MemberAccess("block.timestamp".into()),
                    label: "block_data".into(),
                },
                TaintSource {
                    pattern: SourcePattern::Parameter,
                    label: "parameter".into(),
                },
            ],
            sanitizers: vec![],
            sinks: vec![
                TaintSink {
                    rule_id: "solidity/reentrancy".into(),
                    pattern: SinkPattern::FunctionCall("call".into()),
                },
                TaintSink {
                    rule_id: "solidity/delegatecall".into(),
                    pattern: SinkPattern::FunctionCall("delegatecall".into()),
                },
                TaintSink {
                    rule_id: "solidity/selfdestruct".into(),
                    pattern: SinkPattern::FunctionCall("selfdestruct".into()),
                },
                TaintSink {
                    rule_id: "solidity/transfer".into(),
                    pattern: SinkPattern::FunctionCall("transfer".into()),
                },
                TaintSink {
                    rule_id: "solidity/send".into(),
                    pattern: SinkPattern::FunctionCall("send".into()),
                },
            ],
            source_function_cache: Vec::new(),
            source_member_cache: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_js_source_detection() {
        let config = TaintConfig::javascript();
        assert!(config.is_source_member("req.query"));
        assert!(config.is_source_member("req.body"));
        assert!(config.is_source_member("document.location"));
        assert!(!config.is_source_member("some.random.thing"));
        assert!(config.is_source_function("getElementById"));
        assert!(config.is_source_function("querySelector"));
        assert!(!config.is_source_function("console.log"));
    }

    #[test]
    fn test_js_sanitizer_detection() {
        let config = TaintConfig::javascript();
        assert!(config.is_sanitizer("DOMPurify.sanitize"));
        assert!(config.is_sanitizer("encodeURIComponent"));
        assert!(config.is_sanitizer("textContent"));
        assert!(!config.is_sanitizer("innerHTML"));
    }

    #[test]
    fn test_js_sink_detection() {
        let config = TaintConfig::javascript();
        assert!(config.is_sink_property("innerHTML"));
        assert!(config.is_sink_property("outerHTML"));
        assert!(!config.is_sink_property("textContent"));
        assert!(config.is_sink_function("eval"));
    }
}
