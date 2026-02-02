//! Dataflow-powered rules for code quality and security analysis
//!
//! These rules use the dataflow analysis framework to detect:
//! - Dead stores (assignments that are never read)
//! - Unused variables (declarations that are never used)
//! - Cross-function taint flows (taint crossing function boundaries)
//! - Path traversal vulnerabilities (user input flowing to file operations)
//! - SSRF vulnerabilities (user-controlled URLs flowing to HTTP clients)
//!
//! These rules are language-agnostic and work with the CFG and dataflow results.

use crate::flow::{FlowContext, TaintKind, TaintLevel};
use crate::rules::{Rule, create_finding_at_line};
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use std::sync::LazyLock;

// =============================================================================
// Dead Store Rule
// =============================================================================

/// Detects dead stores: assignments to variables that are never read before
/// being overwritten or going out of scope.
///
/// Dead stores indicate:
/// - Unnecessary computation
/// - Potential bugs (intended to use the variable but forgot)
/// - Leftover code from refactoring
pub struct DeadStoreRule;

impl Rule for DeadStoreRule {
    fn id(&self) -> &str {
        "generic/dead-store"
    }

    fn description(&self) -> &str {
        "Variable is assigned but never read before being overwritten or going out of scope"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        // Works for all languages with dataflow support
        true
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        // Requires dataflow analysis
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get dead stores from def-use chains
        let dead_stores = flow.dead_stores();

        for def in dead_stores {
            // Skip common false positives
            if should_skip_variable(&def.var_name) {
                continue;
            }

            // Skip if in test file
            if super::generic::is_test_or_fixture_file(&parsed.path) {
                continue;
            }

            let mut finding = create_finding_at_line(
                self.id(),
                &parsed.path,
                def.line,
                &format!("{} = ...", def.var_name),
                Severity::Info,
                &format!(
                    "Variable '{}' is assigned on line {} but never read",
                    def.var_name, def.line
                ),
                parsed.language,
            );
            finding.confidence = Confidence::Medium;
            findings.push(finding);
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Unused Variable Rule
// =============================================================================

/// Detects unused variables: variables that are declared but never referenced.
///
/// Unused variables indicate:
/// - Dead code
/// - Incomplete implementation
/// - Copy-paste errors
pub struct UnusedVariableRule;

impl Rule for UnusedVariableRule {
    fn id(&self) -> &str {
        "generic/unused-variable"
    }

    fn description(&self) -> &str {
        "Variable is declared but never used"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check def-use chains for definitions with no uses
        if let Some(chains) = flow.def_use_chains() {
            for (def, uses) in &chains.def_to_uses {
                if uses.is_empty() && !should_skip_variable(&def.var_name) {
                    // Skip test files
                    if super::generic::is_test_or_fixture_file(&parsed.path) {
                        continue;
                    }

                    // Only report if the variable is actually defined (not just a declaration)
                    // Parameters are expected to potentially be unused
                    if matches!(
                        def.origin,
                        crate::flow::reaching_defs::DefOrigin::Parameter(_)
                    ) {
                        continue;
                    }

                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        def.line,
                        &def.var_name,
                        Severity::Info,
                        &format!(
                            "Variable '{}' is declared on line {} but never used",
                            def.var_name, def.line
                        ),
                        parsed.language,
                    );
                    finding.confidence = Confidence::Medium;
                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Cross-Function Taint Rule
// =============================================================================

/// Detects cross-function taint flows: taint originating in one function
/// that reaches a sink in another function.
///
/// These flows are harder to track manually and represent security risks:
/// - Input validation bypass (validation in wrong function)
/// - Unintended data exposure
/// - Complex attack vectors
pub struct CrossFunctionTaintRule;

impl Rule for CrossFunctionTaintRule {
    fn id(&self) -> &str {
        "generic/cross-function-taint"
    }

    fn description(&self) -> &str {
        "Tainted data flows from one function to a sink in another function"
    }

    fn applies_to(&self, _lang: Language) -> bool {
        true
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Get interprocedural taint flows
        if let Some(interproc) = flow.interprocedural_result() {
            for taint_flow in interproc.interprocedural_flows() {
                // Skip test files
                if super::generic::is_test_or_fixture_file(&parsed.path) {
                    continue;
                }

                let functions_str = taint_flow.functions_involved.join(" -> ");
                let kind_str = format!("{:?}", taint_flow.source.kind);

                let mut finding = create_finding_at_line(
                    self.id(),
                    &parsed.path,
                    taint_flow.sink.line,
                    &taint_flow.sink.name,
                    Severity::Error,
                    &format!(
                        "Tainted data ({}) flows from '{}' (line {}) to sink '{}' (line {}) across functions: {}",
                        kind_str,
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        functions_str
                    ),
                    parsed.language,
                );
                finding.confidence = Confidence::Medium;
                findings.push(finding);
            }
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Uninitialized Variable Rule
// =============================================================================

/// Detects potential use of uninitialized variables.
///
/// Uses reaching definitions: if a variable is used at a point where
/// no definition reaches, it may be uninitialized.
pub struct UninitializedVariableRule;

impl Rule for UninitializedVariableRule {
    fn id(&self) -> &str {
        "generic/uninitialized-variable"
    }

    fn description(&self) -> &str {
        "Variable may be used before being initialized"
    }

    fn applies_to(&self, lang: Language) -> bool {
        // Most useful for languages without strict initialization
        matches!(
            lang,
            Language::JavaScript | Language::TypeScript | Language::Python
        )
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for uses without reaching definitions
        if let Some(chains) = flow.def_use_chains() {
            for (use_site, defs) in &chains.use_to_defs {
                if defs.is_empty() && !should_skip_variable(&use_site.var_name) {
                    // Skip test files
                    if super::generic::is_test_or_fixture_file(&parsed.path) {
                        continue;
                    }

                    // Skip global/builtin names
                    if is_likely_global(&use_site.var_name) {
                        continue;
                    }

                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        use_site.line,
                        &use_site.var_name,
                        Severity::Warning,
                        &format!(
                            "Variable '{}' may be used on line {} before being initialized",
                            use_site.var_name, use_site.line
                        ),
                        parsed.language,
                    );
                    finding.confidence = Confidence::Low; // Conservative
                    findings.push(finding);
                }
            }
        }

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Path Traversal Taint Rule
// =============================================================================

/// Detects path traversal vulnerabilities using taint analysis.
///
/// Path traversal (directory traversal) occurs when user-controlled input is used
/// to construct file paths without proper validation, allowing attackers to access
/// files outside intended directories using sequences like `../`.
///
/// This rule uses the taint tracking infrastructure to:
/// 1. Identify sources of user input that could contain path traversal sequences
/// 2. Track the flow of tainted data through the program
/// 3. Flag when tainted data reaches file system operations (sinks)
/// 4. Recognize sanitizers that neutralize path traversal attacks
pub struct PathTraversalTaintRule;

impl PathTraversalTaintRule {
    /// Sources of user input that could contain path traversal sequences
    const JS_SOURCES: &'static [&'static str] = &[
        // Express.js / Node.js HTTP
        "req.params",
        "req.query",
        "req.body",
        "request.params",
        "request.query",
        "request.body",
        // Specific path-related parameters
        "req.params.filename",
        "req.params.path",
        "req.params.file",
        "req.query.filename",
        "req.query.path",
        "req.query.file",
        "req.body.filename",
        "req.body.path",
        "req.body.file",
    ];

    const PYTHON_SOURCES: &'static [&'static str] = &[
        // Flask
        "request.args",
        "request.form",
        "request.files",
        "request.values",
        // Django
        "request.GET",
        "request.POST",
        "request.FILES",
        // FastAPI / path parameters
        "filename",
        "file_path",
        "filepath",
    ];

    const GO_SOURCES: &'static [&'static str] = &[
        // net/http
        "r.URL.Query",
        "r.FormValue",
        "r.PostFormValue",
        "r.PathValue",
        // Gin
        "c.Param",
        "c.Query",
        "c.PostForm",
        // Echo
        "c.QueryParam",
        "c.FormValue",
    ];

    const JAVA_SOURCES: &'static [&'static str] = &[
        // Servlet API
        "request.getParameter",
        "request.getPathInfo",
        "request.getServletPath",
        // Spring MVC
        "@PathVariable",
        "@RequestParam",
        // Common parameter names
        "filename",
        "filePath",
        "path",
    ];

    /// Sinks - file operations where path traversal is dangerous
    const JS_SINKS: &'static [&'static str] = &[
        // fs module
        "fs.readFile",
        "fs.readFileSync",
        "fs.writeFile",
        "fs.writeFileSync",
        "fs.open",
        "fs.openSync",
        "fs.access",
        "fs.accessSync",
        "fs.stat",
        "fs.statSync",
        "fs.unlink",
        "fs.unlinkSync",
        "fs.mkdir",
        "fs.mkdirSync",
        "fs.rmdir",
        "fs.rmdirSync",
        "fs.readdir",
        "fs.readdirSync",
        "fs.createReadStream",
        "fs.createWriteStream",
        // fs/promises
        "fs.promises.readFile",
        "fs.promises.writeFile",
        "fs.promises.open",
        // path module (can be used dangerously)
        "path.join",
        "path.resolve",
        // require/import with dynamic paths
        "require",
        "import",
    ];

    const PYTHON_SINKS: &'static [&'static str] = &[
        // Built-in file operations
        "open",
        "file",
        // os module
        "os.path.join",
        "os.open",
        "os.read",
        "os.write",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.mkdir",
        "os.makedirs",
        "os.listdir",
        "os.stat",
        "os.access",
        // pathlib
        "Path",
        "pathlib.Path",
        "PurePath",
        // shutil
        "shutil.copy",
        "shutil.copy2",
        "shutil.move",
        "shutil.rmtree",
        // io module
        "io.open",
        "io.FileIO",
        // Flask specific
        "send_file",
        "send_from_directory",
    ];

    const GO_SINKS: &'static [&'static str] = &[
        // os package
        "os.Open",
        "os.OpenFile",
        "os.Create",
        "os.ReadFile",
        "os.WriteFile",
        "os.Remove",
        "os.RemoveAll",
        "os.Mkdir",
        "os.MkdirAll",
        "os.Stat",
        "os.Lstat",
        "os.ReadDir",
        // ioutil (deprecated but still used)
        "ioutil.ReadFile",
        "ioutil.WriteFile",
        "ioutil.ReadDir",
        // filepath package
        "filepath.Join",
        "filepath.Clean",
        // http package
        "http.ServeFile",
        "http.FileServer",
    ];

    const JAVA_SINKS: &'static [&'static str] = &[
        // java.io
        "new File",
        "File",
        "FileInputStream",
        "FileOutputStream",
        "FileReader",
        "FileWriter",
        "RandomAccessFile",
        // java.nio
        "Files.readAllBytes",
        "Files.readString",
        "Files.write",
        "Files.writeString",
        "Files.copy",
        "Files.move",
        "Files.delete",
        "Files.createFile",
        "Files.createDirectory",
        "Files.list",
        "Files.walk",
        "Paths.get",
        "Path.of",
        // Spring
        "ResourceLoader.getResource",
        "ClassPathResource",
    ];

    /// Sanitizers that neutralize path traversal attacks
    #[allow(dead_code)]
    const JS_SANITIZERS: &'static [&'static str] = &[
        "path.basename",  // Extracts only the filename
        "path.normalize", // Resolves ../ sequences (but doesn't prevent escape alone)
        "path.resolve",   // When used with startsWith check
        "sanitize",       // Generic sanitize functions
        "sanitizeFilename",
        "validatePath",
    ];

    #[allow(dead_code)]
    const PYTHON_SANITIZERS: &'static [&'static str] = &[
        "os.path.basename", // Extracts only the filename
        "os.path.realpath", // Resolves to canonical path (needs startswith check)
        "os.path.abspath",  // Resolves to absolute path
        "secure_filename",  // Werkzeug's secure_filename
        "sanitize_filename",
        "validate_path",
    ];

    #[allow(dead_code)]
    const GO_SANITIZERS: &'static [&'static str] = &[
        "filepath.Base",  // Extracts only the filename
        "filepath.Clean", // Cleans the path
        "filepath.Abs",   // When combined with prefix check
        "SecureJoin",     // go-securejoin
        "sanitizePath",
        "validatePath",
    ];

    #[allow(dead_code)]
    const JAVA_SANITIZERS: &'static [&'static str] = &[
        "getCanonicalPath",      // Resolves to canonical path (needs startsWith check)
        "toRealPath",            // Resolves symlinks
        "normalize",             // Path.normalize()
        "FilenameUtils.getName", // Apache Commons IO
        "sanitizeFilename",
        "validatePath",
    ];

    /// Check if a variable name or expression matches a source pattern
    fn is_path_source(&self, expr: &str, language: Language) -> bool {
        let sources = match language {
            Language::JavaScript | Language::TypeScript => Self::JS_SOURCES,
            Language::Python => Self::PYTHON_SOURCES,
            Language::Go => Self::GO_SOURCES,
            Language::Java => Self::JAVA_SOURCES,
            _ => return false,
        };

        let expr_lower = expr.to_lowercase();
        sources.iter().any(|src| {
            let src_lower = src.to_lowercase();
            expr_lower.contains(&src_lower) || src_lower.contains(&expr_lower)
        })
    }

    /// Check if a function call is a path traversal sink
    fn is_path_sink(&self, func_name: &str, language: Language) -> bool {
        let sinks = match language {
            Language::JavaScript | Language::TypeScript => Self::JS_SINKS,
            Language::Python => Self::PYTHON_SINKS,
            Language::Go => Self::GO_SINKS,
            Language::Java => Self::JAVA_SINKS,
            _ => return false,
        };

        let func_lower = func_name.to_lowercase();
        sinks.iter().any(|sink| {
            let sink_lower = sink.to_lowercase();
            func_lower.contains(&sink_lower) || func_lower.ends_with(&sink_lower)
        })
    }

    /// Get remediation suggestion based on language
    fn get_suggestion(&self, language: Language) -> &'static str {
        match language {
            Language::JavaScript | Language::TypeScript => {
                "Use path.basename() to extract only the filename, or validate the resolved path starts with your intended base directory using path.resolve() with a startsWith check."
            }
            Language::Python => {
                "Use os.path.basename() to extract only the filename, or use os.path.realpath() and verify the result starts with your intended base directory."
            }
            Language::Go => {
                "Use filepath.Base() to extract only the filename, or use filepath.Clean() combined with strings.HasPrefix() to validate the path stays within bounds."
            }
            Language::Java => {
                "Use getCanonicalPath() and verify the result starts with your intended base directory, or use FilenameUtils.getName() from Apache Commons IO."
            }
            _ => {
                "Validate that file paths cannot escape the intended directory using basename extraction or canonical path validation."
            }
        }
    }
}

impl Rule for PathTraversalTaintRule {
    fn id(&self) -> &str {
        "security/path-traversal-taint"
    }

    fn description(&self) -> &str {
        "Detects path traversal vulnerabilities where user input flows to file operations"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(
            lang,
            Language::JavaScript
                | Language::TypeScript
                | Language::Python
                | Language::Go
                | Language::Java
        )
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        // Requires dataflow analysis
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Skip test files
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        // Get interprocedural taint flows
        if let Some(interproc) = flow.interprocedural_result() {
            // Check for FilePath taint flows specifically
            for taint_flow in interproc.flows_by_kind(crate::flow::TaintKind::FilePath) {
                // Check if the sink is a file operation
                if self.is_path_sink(&taint_flow.sink.name, parsed.language) {
                    let message = format!(
                        "Path traversal vulnerability: user input '{}' (line {}) flows to file operation '{}' (line {}). {}",
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        self.get_suggestion(parsed.language)
                    );

                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        taint_flow.sink.line,
                        &taint_flow.sink.name,
                        Severity::Error,
                        &message,
                        parsed.language,
                    );
                    finding.confidence = Confidence::High;
                    finding.suggestion = Some(self.get_suggestion(parsed.language).to_string());
                    findings.push(finding);
                }
            }

            // Also check UserInput flows that reach file sinks
            for taint_flow in interproc.flows_by_kind(crate::flow::TaintKind::UserInput) {
                if self.is_path_sink(&taint_flow.sink.name, parsed.language) {
                    let message = format!(
                        "Potential path traversal: user input '{}' (line {}) may flow to file operation '{}' (line {}). {}",
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        self.get_suggestion(parsed.language)
                    );

                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        taint_flow.sink.line,
                        &taint_flow.sink.name,
                        Severity::Warning,
                        &message,
                        parsed.language,
                    );
                    finding.confidence = Confidence::Medium;
                    finding.suggestion = Some(self.get_suggestion(parsed.language).to_string());
                    findings.push(finding);
                }
            }
        }

        // Also check symbol table for direct taint to file operations
        for (var_name, _info) in flow.symbols.iter() {
            // Skip if this variable is not tainted
            if !flow.is_tainted(var_name) {
                continue;
            }

            // Check if the variable name suggests it's used for file paths
            let var_lower = var_name.to_lowercase();
            let is_path_var = var_lower.contains("path")
                || var_lower.contains("file")
                || var_lower.contains("filename")
                || var_lower.contains("dir")
                || var_lower.contains("folder");

            // Check if it comes from a user input source
            if is_path_var && self.is_path_source(var_name, parsed.language) {
                // Check if this variable is used in any file operation call sites
                if let Some(interproc) = flow.interprocedural_result() {
                    for call_site in &interproc.call_sites {
                        if self.is_path_sink(&call_site.callee_name, parsed.language) {
                            // Check if any argument references our tainted variable
                            for arg in &call_site.arguments {
                                if arg.var_name.as_ref().is_some_and(|n| n == var_name)
                                    || arg.expr.contains(var_name)
                                {
                                    let message = format!(
                                        "Path traversal risk: tainted variable '{}' used in file operation '{}' on line {}. {}",
                                        var_name,
                                        call_site.callee_name,
                                        call_site.line,
                                        self.get_suggestion(parsed.language)
                                    );

                                    let mut finding = create_finding_at_line(
                                        self.id(),
                                        &parsed.path,
                                        call_site.line,
                                        &call_site.callee_name,
                                        Severity::Warning,
                                        &message,
                                        parsed.language,
                                    );
                                    finding.confidence = Confidence::Medium;
                                    finding.suggestion =
                                        Some(self.get_suggestion(parsed.language).to_string());
                                    findings.push(finding);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Deduplicate findings by location
        findings.sort_by_key(|f| (f.location.start_line, f.location.start_column));
        findings.dedup_by(|a, b| {
            a.location.start_line == b.location.start_line
                && a.location.start_column == b.location.start_column
        });

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Command Injection Taint Rule
// =============================================================================

/// Detects command injection vulnerabilities using taint analysis.
///
/// Command injection occurs when user-controlled input is used to construct
/// shell commands without proper validation, allowing attackers to execute
/// arbitrary commands on the system.
///
/// This rule uses the taint tracking infrastructure to:
/// 1. Identify sources of user input that could contain malicious commands
/// 2. Track the flow of tainted data through the program
/// 3. Flag when tainted data reaches command execution functions (sinks)
/// 4. Recognize sanitizers that neutralize command injection attacks
/// 5. Distinguish between shell mode (critical) and array args (safer)
pub struct CommandInjectionTaintRule;

impl CommandInjectionTaintRule {
    // =========================================================================
    // Sources - user-controlled input that could contain malicious commands
    // =========================================================================

    const JS_SOURCES: &'static [&'static str] = &[
        "req.query",
        "req.body",
        "req.params",
        "request.query",
        "request.body",
        "request.params",
        "process.argv",
        "process.env",
        "process.stdin",
        "url.searchParams",
    ];

    const PYTHON_SOURCES: &'static [&'static str] = &[
        "request.args",
        "request.form",
        "request.values",
        "request.json",
        "request.GET",
        "request.POST",
        "sys.argv",
        "os.environ",
        "os.getenv",
        "input",
        "sys.stdin",
    ];

    const GO_SOURCES: &'static [&'static str] = &[
        "r.URL.Query",
        "r.FormValue",
        "r.PostFormValue",
        "r.PathValue",
        "os.Args",
        "os.Getenv",
        "os.LookupEnv",
        "c.Param",
        "c.Query",
        "c.PostForm",
        "c.QueryParam",
        "c.FormValue",
        "bufio.Scanner",
    ];

    const RUST_SOURCES: &'static [&'static str] = &[
        "std::env::args",
        "env::args",
        "args",
        "std::env::var",
        "env::var",
        "var",
        "env::var_os",
        "std::io::stdin",
        "io::stdin",
        "Query",
        "Form",
        "Path",
        "Json",
    ];

    const JAVA_SOURCES: &'static [&'static str] = &[
        "request.getParameter",
        "request.getParameterValues",
        "request.getQueryString",
        "request.getInputStream",
        "System.getenv",
        "System.getProperty",
        "args",
        "System.in",
        "Scanner",
        "@RequestParam",
        "@PathVariable",
        "@RequestBody",
    ];

    // =========================================================================
    // Sinks - command execution functions
    // =========================================================================

    const JS_SINKS: &'static [&'static str] = &[
        "child_process.exec",
        "child_process.execSync",
        "child_process.spawn",
        "child_process.spawnSync",
        "child_process.execFile",
        "child_process.execFileSync",
        "child_process.fork",
        "shell.exec",
        "execa",
        "execaSync",
        "shelljs.exec",
    ];

    const PYTHON_SINKS: &'static [&'static str] = &[
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getstatusoutput",
        "subprocess.getoutput",
        "os.system",
        "os.popen",
        "os.popen2",
        "os.popen3",
        "os.popen4",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "commands.getoutput",
        "commands.getstatusoutput",
    ];

    const GO_SINKS: &'static [&'static str] = &[
        "exec.Command",
        "exec.CommandContext",
        "os.StartProcess",
        "syscall.Exec",
        "syscall.ForkExec",
    ];

    const RUST_SINKS: &'static [&'static str] = &[
        "Command::new",
        "std::process::Command::new",
        "process::Command::new",
        "tokio::process::Command::new",
        "async_std::process::Command::new",
    ];

    const JAVA_SINKS: &'static [&'static str] = &[
        "Runtime.getRuntime",
        "Runtime.exec",
        "runtime.exec",
        "ProcessBuilder",
        "new ProcessBuilder",
        "CommandLine",
        "DefaultExecutor",
        "Executor.execute",
    ];

    /// Patterns indicating shell mode is enabled (highest risk)
    const SHELL_MODE_PATTERNS: &'static [&'static str] = &[
        "shell=True",
        "shell = True",
        "shell: true",
        "shell:true",
        "sh -c",
        "bash -c",
        "cmd /c",
        "cmd.exe /c",
        "powershell -c",
        "pwsh -c",
        "/bin/sh",
        "/bin/bash",
    ];

    fn is_command_source(&self, expr: &str, language: Language) -> bool {
        let sources = match language {
            Language::JavaScript | Language::TypeScript => Self::JS_SOURCES,
            Language::Python => Self::PYTHON_SOURCES,
            Language::Go => Self::GO_SOURCES,
            Language::Rust => Self::RUST_SOURCES,
            Language::Java => Self::JAVA_SOURCES,
            _ => return false,
        };
        let expr_lower = expr.to_lowercase();
        sources.iter().any(|src| {
            let src_lower = src.to_lowercase();
            expr_lower.contains(&src_lower) || src_lower.contains(&expr_lower)
        })
    }

    fn is_command_sink(&self, func_name: &str, language: Language) -> bool {
        let sinks = match language {
            Language::JavaScript | Language::TypeScript => Self::JS_SINKS,
            Language::Python => Self::PYTHON_SINKS,
            Language::Go => Self::GO_SINKS,
            Language::Rust => Self::RUST_SINKS,
            Language::Java => Self::JAVA_SINKS,
            _ => return false,
        };
        let func_lower = func_name.to_lowercase();
        sinks.iter().any(|sink| {
            let sink_lower = sink.to_lowercase();
            func_lower.contains(&sink_lower) || func_lower.ends_with(&sink_lower)
        })
    }

    fn has_shell_mode(&self, code_context: &str) -> bool {
        let context_lower = code_context.to_lowercase();
        Self::SHELL_MODE_PATTERNS
            .iter()
            .any(|pattern| context_lower.contains(&pattern.to_lowercase()))
    }

    fn get_suggestion(&self, language: Language, is_shell_mode: bool) -> String {
        match language {
            Language::JavaScript | Language::TypeScript => {
                if is_shell_mode {
                    "CRITICAL: Avoid shell mode. Use execFile() or spawn() with array arguments. If shell mode is required, use shell-escape."
                } else {
                    "Pass command arguments as an array to spawn() or execFile(). Never construct command strings from user input."
                }
            }
            Language::Python => {
                if is_shell_mode {
                    "CRITICAL: Avoid shell=True with subprocess. Pass command as a list. If shell mode is required, use shlex.quote()."
                } else {
                    "Pass command as a list to subprocess functions instead of a string. Use shlex.quote() if you must include user input."
                }
            }
            Language::Go => {
                "Pass command arguments as separate strings to exec.Command() instead of constructing a shell command. Never use 'sh -c' with user input."
            }
            Language::Rust => {
                "Pass arguments to Command::new().arg() separately instead of concatenating. Use shell-escape crate if shell expansion is needed."
            }
            Language::Java => {
                if is_shell_mode {
                    "CRITICAL: Avoid passing command strings to Runtime. Use ProcessBuilder with separate arguments."
                } else {
                    "Use ProcessBuilder with command and arguments as separate strings. Never concatenate user input into command strings."
                }
            }
            _ => "Avoid constructing shell commands from user input. Use parameterized APIs or proper escaping.",
        }.to_string()
    }

    fn determine_severity(&self, is_shell_mode: bool) -> Severity {
        if is_shell_mode {
            Severity::Error
        } else {
            Severity::Warning
        }
    }
}

impl Rule for CommandInjectionTaintRule {
    fn id(&self) -> &str {
        "security/command-injection-taint"
    }
    fn description(&self) -> &str {
        "Detects command injection vulnerabilities where user input flows to command execution"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(
            lang,
            Language::JavaScript
                | Language::TypeScript
                | Language::Python
                | Language::Go
                | Language::Rust
                | Language::Java
        )
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        if let Some(interproc) = flow.interprocedural_result() {
            for taint_flow in interproc.flows_by_kind(TaintKind::Command) {
                if self.is_command_sink(&taint_flow.sink.name, parsed.language) {
                    let is_shell_mode = self.has_shell_mode(&taint_flow.sink.name);
                    let severity = self.determine_severity(is_shell_mode);
                    let risk_level = if is_shell_mode { "CRITICAL" } else { "High" };
                    let message = format!(
                        "Command injection vulnerability ({}): user input '{}' (line {}) flows to command execution '{}' (line {}). {}",
                        risk_level,
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        self.get_suggestion(parsed.language, is_shell_mode)
                    );
                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        taint_flow.sink.line,
                        &taint_flow.sink.name,
                        severity,
                        &message,
                        parsed.language,
                    );
                    finding.confidence = Confidence::High;
                    finding.suggestion = Some(self.get_suggestion(parsed.language, is_shell_mode));
                    findings.push(finding);
                }
            }

            for taint_flow in interproc.flows_by_kind(TaintKind::UserInput) {
                if self.is_command_sink(&taint_flow.sink.name, parsed.language) {
                    let is_shell_mode = self.has_shell_mode(&taint_flow.sink.name);
                    let severity = self.determine_severity(is_shell_mode);
                    let message = format!(
                        "Potential command injection: user input '{}' (line {}) may flow to command execution '{}' (line {}). {}",
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        self.get_suggestion(parsed.language, is_shell_mode)
                    );
                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        taint_flow.sink.line,
                        &taint_flow.sink.name,
                        severity,
                        &message,
                        parsed.language,
                    );
                    finding.confidence = Confidence::Medium;
                    finding.suggestion = Some(self.get_suggestion(parsed.language, is_shell_mode));
                    findings.push(finding);
                }
            }
        }

        for (var_name, _info) in flow.symbols.iter() {
            if !flow.is_tainted(var_name) {
                continue;
            }
            let var_lower = var_name.to_lowercase();
            let is_cmd_var = var_lower.contains("cmd")
                || var_lower.contains("command")
                || var_lower.contains("shell")
                || var_lower.contains("script");
            if is_cmd_var || self.is_command_source(var_name, parsed.language) {
                if let Some(interproc) = flow.interprocedural_result() {
                    for call_site in &interproc.call_sites {
                        if self.is_command_sink(&call_site.callee_name, parsed.language) {
                            for arg in &call_site.arguments {
                                if arg.var_name.as_ref().is_some_and(|n| n == var_name)
                                    || arg.expr.contains(var_name)
                                {
                                    let is_shell_mode = self.has_shell_mode(&call_site.callee_name);
                                    let severity = self.determine_severity(is_shell_mode);
                                    let message = format!(
                                        "Command injection risk: tainted variable '{}' used in command execution '{}' on line {}. {}",
                                        var_name,
                                        call_site.callee_name,
                                        call_site.line,
                                        self.get_suggestion(parsed.language, is_shell_mode)
                                    );
                                    let mut finding = create_finding_at_line(
                                        self.id(),
                                        &parsed.path,
                                        call_site.line,
                                        &call_site.callee_name,
                                        severity,
                                        &message,
                                        parsed.language,
                                    );
                                    finding.confidence = Confidence::Medium;
                                    finding.suggestion =
                                        Some(self.get_suggestion(parsed.language, is_shell_mode));
                                    findings.push(finding);
                                }
                            }
                        }
                    }
                }
            }
        }

        findings.sort_by_key(|f| (f.location.start_line, f.location.start_column));
        findings.dedup_by(|a, b| {
            a.location.start_line == b.location.start_line
                && a.location.start_column == b.location.start_column
        });
        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// SQL Injection Taint Rule
// =============================================================================

/// Detects SQL injection vulnerabilities using taint tracking.
///
/// SQL injection occurs when untrusted user input is incorporated into SQL queries
/// without proper sanitization or parameterization. Attackers can manipulate queries
/// to access unauthorized data, modify database contents, or execute administrative operations.
///
/// This rule uses the taint tracking infrastructure to:
/// 1. Identify sources of user input that could contain malicious SQL
/// 2. Track the flow of tainted data through the program
/// 3. Flag when tainted data reaches SQL execution sinks
/// 4. Recognize sanitizers like parameterized queries (?, $1, :name placeholders)
pub struct SqlInjectionTaintRule;

impl SqlInjectionTaintRule {
    /// SQL sinks for JavaScript/TypeScript
    const JS_SQL_SINKS: &'static [&'static str] = &[
        // Generic database methods
        "query",
        "execute",
        "exec",
        "run",
        // MySQL
        "mysql.query",
        "mysql.execute",
        "connection.query",
        "connection.execute",
        "pool.query",
        "pool.execute",
        // PostgreSQL (pg)
        "pg.query",
        "client.query",
        "pool.query",
        // Prisma
        "$queryRaw",
        "$executeRaw",
        "$queryRawUnsafe",
        "$executeRawUnsafe",
        // Knex
        "knex.raw",
        "raw",
        // Sequelize
        "sequelize.query",
        // Better-sqlite3
        "db.prepare",
        "db.exec",
        // TypeORM
        "createQueryBuilder",
        "manager.query",
        // MongoDB (NoSQL injection)
        "collection.find",
        "collection.findOne",
        "collection.aggregate",
        "db.collection",
    ];

    /// SQL sinks for Python
    const PYTHON_SQL_SINKS: &'static [&'static str] = &[
        // DB-API 2.0 standard
        "cursor.execute",
        "cursor.executemany",
        "cursor.executescript",
        "connection.execute",
        "conn.execute",
        "db.execute",
        // SQLAlchemy
        "session.execute",
        "engine.execute",
        "text",
        "raw_connection",
        // Django ORM
        "raw",
        "extra",
        "RawSQL",
        "cursor.execute",
        // psycopg2
        "cur.execute",
        "cursor.execute",
        // sqlite3
        "execute",
        "executemany",
        "executescript",
        // asyncpg
        "connection.fetch",
        "connection.execute",
        // MongoDB (pymongo)
        "collection.find",
        "collection.find_one",
        "collection.aggregate",
    ];

    /// SQL sinks for Go
    const GO_SQL_SINKS: &'static [&'static str] = &[
        // database/sql
        "db.Query",
        "db.QueryRow",
        "db.QueryContext",
        "db.QueryRowContext",
        "db.Exec",
        "db.ExecContext",
        "db.Prepare",
        "db.PrepareContext",
        "tx.Query",
        "tx.QueryRow",
        "tx.Exec",
        "stmt.Query",
        "stmt.QueryRow",
        "stmt.Exec",
        // GORM
        "db.Raw",
        "db.Exec",
        "db.Where",
        "tx.Raw",
        // sqlx
        "sqlx.Query",
        "sqlx.QueryRow",
        "sqlx.Exec",
        "sqlx.Get",
        "sqlx.Select",
        // MongoDB
        "collection.Find",
        "collection.FindOne",
        "collection.Aggregate",
    ];

    /// SQL sinks for Java
    const JAVA_SQL_SINKS: &'static [&'static str] = &[
        // JDBC
        "Statement.execute",
        "Statement.executeQuery",
        "Statement.executeUpdate",
        "Statement.executeBatch",
        "PreparedStatement.execute",
        "PreparedStatement.executeQuery",
        "PreparedStatement.executeUpdate",
        "connection.createStatement",
        "connection.prepareStatement",
        // Hibernate
        "session.createQuery",
        "session.createSQLQuery",
        "session.createNativeQuery",
        // JPA
        "entityManager.createQuery",
        "entityManager.createNativeQuery",
        // Spring JDBC
        "jdbcTemplate.query",
        "jdbcTemplate.queryForObject",
        "jdbcTemplate.queryForList",
        "jdbcTemplate.execute",
        "jdbcTemplate.update",
        "namedParameterJdbcTemplate.query",
        // MyBatis
        "sqlSession.selectOne",
        "sqlSession.selectList",
        "sqlSession.insert",
        "sqlSession.update",
        "sqlSession.delete",
    ];

    /// Sources of user input
    #[allow(dead_code)]
    const JS_SOURCES: &'static [&'static str] = &[
        "req.params",
        "req.query",
        "req.body",
        "request.params",
        "request.query",
        "request.body",
        "ctx.params",
        "ctx.query",
        "ctx.request.body",
    ];

    #[allow(dead_code)]
    const PYTHON_SOURCES: &'static [&'static str] = &[
        "request.args",
        "request.form",
        "request.json",
        "request.data",
        "request.GET",
        "request.POST",
    ];

    #[allow(dead_code)]
    const GO_SOURCES: &'static [&'static str] = &[
        "r.URL.Query",
        "r.FormValue",
        "r.PostFormValue",
        "c.Param",
        "c.Query",
        "c.PostForm",
    ];

    #[allow(dead_code)]
    const JAVA_SOURCES: &'static [&'static str] = &[
        "request.getParameter",
        "@RequestParam",
        "@PathVariable",
        "@RequestBody",
    ];

    /// Check if a function call is an SQL sink
    fn is_sql_sink(&self, func_name: &str, language: Language) -> bool {
        let sinks = match language {
            Language::JavaScript | Language::TypeScript => Self::JS_SQL_SINKS,
            Language::Python => Self::PYTHON_SQL_SINKS,
            Language::Go => Self::GO_SQL_SINKS,
            Language::Java => Self::JAVA_SQL_SINKS,
            _ => return false,
        };

        let func_lower = func_name.to_lowercase();
        sinks.iter().any(|sink| {
            let sink_lower = sink.to_lowercase();
            func_lower.contains(&sink_lower) || func_lower.ends_with(&sink_lower)
        })
    }

    /// Check if a query string uses parameterized placeholders (sanitized for SQL)
    fn is_parameterized_query(query: &str) -> bool {
        // Check for common parameterized query patterns
        // ? placeholders (MySQL, SQLite, many others)
        if query.contains('?') {
            return true;
        }
        // $1, $2, etc. (PostgreSQL positional parameters)
        if query.contains("$1") || query.contains("$2") || query.contains("$3") {
            return true;
        }
        // :name placeholders (Oracle, SQLAlchemy named parameters)
        let has_named_param = regex::Regex::new(r":\w+").map_or(false, |re| re.is_match(query));
        if has_named_param {
            return true;
        }
        // @param placeholders (SQL Server, some ORMs)
        if query.contains('@') && regex::Regex::new(r"@\w+").map_or(false, |re| re.is_match(query))
        {
            return true;
        }
        // %s placeholders (Python DB-API)
        if query.contains("%s") || query.contains("%(") {
            return true;
        }
        false
    }

    /// Get remediation suggestion based on language
    fn get_suggestion(&self, language: Language) -> &'static str {
        match language {
            Language::JavaScript | Language::TypeScript => {
                "Use parameterized queries with placeholders (?) instead of string concatenation. Example: db.query('SELECT * FROM users WHERE id = ?', [userId])"
            }
            Language::Python => {
                "Use parameterized queries with placeholders (%s or ?) instead of string formatting. Example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            }
            Language::Go => {
                "Use parameterized queries with placeholders ($1, $2, or ?) instead of fmt.Sprintf. Example: db.Query('SELECT * FROM users WHERE id = $1', userId)"
            }
            Language::Java => {
                "Use PreparedStatement with placeholders (?) instead of Statement with string concatenation. Example: PreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?'); ps.setInt(1, userId);"
            }
            _ => {
                "Use parameterized queries with placeholders instead of string concatenation to prevent SQL injection."
            }
        }
    }
}

impl Rule for SqlInjectionTaintRule {
    fn id(&self) -> &str {
        "security/sql-injection-taint"
    }

    fn description(&self) -> &str {
        "Detects SQL injection vulnerabilities where user input flows to SQL execution"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(
            lang,
            Language::JavaScript
                | Language::TypeScript
                | Language::Python
                | Language::Go
                | Language::Java
        )
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        // Requires dataflow analysis
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Skip test files
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        // Get interprocedural taint flows
        if let Some(interproc) = flow.interprocedural_result() {
            // Check for SQL-specific taint flows
            for taint_flow in interproc.flows_by_kind(crate::flow::TaintKind::SqlQuery) {
                // Check if the sink is an SQL operation
                if self.is_sql_sink(&taint_flow.sink.name, parsed.language) {
                    let message = format!(
                        "SQL injection vulnerability: user input '{}' (line {}) flows to SQL operation '{}' (line {}). {}",
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        self.get_suggestion(parsed.language)
                    );

                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        taint_flow.sink.line,
                        &taint_flow.sink.name,
                        Severity::Error,
                        &message,
                        parsed.language,
                    );
                    finding.confidence = Confidence::High;
                    finding.suggestion = Some(self.get_suggestion(parsed.language).to_string());
                    findings.push(finding);
                }
            }

            // Also check UserInput flows that reach SQL sinks
            for taint_flow in interproc.flows_by_kind(crate::flow::TaintKind::UserInput) {
                if self.is_sql_sink(&taint_flow.sink.name, parsed.language) {
                    let message = format!(
                        "Potential SQL injection: user input '{}' (line {}) may flow to SQL operation '{}' (line {}). {}",
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        self.get_suggestion(parsed.language)
                    );

                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        taint_flow.sink.line,
                        &taint_flow.sink.name,
                        Severity::Warning,
                        &message,
                        parsed.language,
                    );
                    finding.confidence = Confidence::Medium;
                    finding.suggestion = Some(self.get_suggestion(parsed.language).to_string());
                    findings.push(finding);
                }
            }
        }

        // Check symbol table for direct taint to SQL operations
        for (var_name, _info) in flow.symbols.iter() {
            // Skip if this variable is not tainted
            if !flow.is_tainted(var_name) {
                continue;
            }

            // Check if this variable looks like it holds SQL-related data or user input
            let var_lower = var_name.to_lowercase();
            let is_sql_related = var_lower.contains("query")
                || var_lower.contains("sql")
                || var_lower.contains("stmt")
                || var_lower.contains("statement");

            let is_user_input = var_lower.contains("input")
                || var_lower.contains("param")
                || var_lower.contains("user");

            // Check if tainted variable is used in SQL sink call sites
            if is_sql_related || is_user_input {
                if let Some(interproc) = flow.interprocedural_result() {
                    for call_site in &interproc.call_sites {
                        if self.is_sql_sink(&call_site.callee_name, parsed.language) {
                            // Check if any argument references our tainted variable
                            for arg in &call_site.arguments {
                                // Check if the argument uses the tainted variable
                                let uses_tainted =
                                    arg.var_name.as_ref().is_some_and(|n| n == var_name)
                                        || arg.expr.contains(var_name);

                                // Skip if the query is parameterized (sanitized)
                                if uses_tainted && !Self::is_parameterized_query(&arg.expr) {
                                    // Check for string concatenation patterns
                                    let has_concat = arg.expr.contains('+')
                                        || arg.expr.contains("format")
                                        || arg.expr.contains("sprintf")
                                        || arg.expr.contains('$')
                                        || arg.expr.contains('{');

                                    let (severity, confidence) = if has_concat {
                                        // HIGH confidence if we see explicit concatenation
                                        (Severity::Error, Confidence::High)
                                    } else {
                                        // MEDIUM confidence if just tainted flow
                                        (Severity::Warning, Confidence::Medium)
                                    };

                                    let message = format!(
                                        "SQL injection risk: tainted variable '{}' used in SQL operation '{}' on line {}{}. {}",
                                        var_name,
                                        call_site.callee_name,
                                        call_site.line,
                                        if has_concat {
                                            " with string concatenation"
                                        } else {
                                            ""
                                        },
                                        self.get_suggestion(parsed.language)
                                    );

                                    let mut finding = create_finding_at_line(
                                        self.id(),
                                        &parsed.path,
                                        call_site.line,
                                        &call_site.callee_name,
                                        severity,
                                        &message,
                                        parsed.language,
                                    );
                                    finding.confidence = confidence;
                                    finding.suggestion =
                                        Some(self.get_suggestion(parsed.language).to_string());
                                    findings.push(finding);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Deduplicate findings by location
        findings.sort_by_key(|f| (f.location.start_line, f.location.start_column));
        findings.dedup_by(|a, b| {
            a.location.start_line == b.location.start_line
                && a.location.start_column == b.location.start_column
        });

        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// SSRF (Server-Side Request Forgery) Taint Rule
// =============================================================================

/// Detects Server-Side Request Forgery (SSRF) vulnerabilities using taint tracking.
///
/// SSRF occurs when an attacker can control the URL that a server-side application
/// uses to make HTTP requests. This can lead to:
/// - Internal network scanning
/// - Access to internal services (metadata APIs, databases)
/// - Reading files via file:// protocol
/// - Denial of service
///
/// This rule uses the taint tracking infrastructure to:
/// 1. Identify sources of user-controlled URLs
/// 2. Track the flow of tainted data through the program
/// 3. Flag when tainted data reaches HTTP client sinks
/// 4. Recognize sanitizers (URL allowlists, private IP blocking, scheme validation)
/// 5. Flag when URL is a variable rather than a string literal
pub struct SsrfTaintRule;

/// Private IP patterns for SSRF detection
static PRIVATE_IP_PATTERNS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "127.", // Loopback
        "10.",  // Class A private
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",         // Class B private
        "192.168.",        // Class C private
        "169.254.",        // Link-local
        "0.0.0.0",         // All interfaces
        "localhost",       // Localhost hostname
        "[::1]",           // IPv6 loopback
        "[::ffff:127",     // IPv4-mapped IPv6 loopback
        "metadata",        // Cloud metadata endpoints
        "169.254.169.254", // AWS/GCP metadata
    ]
});

impl SsrfTaintRule {
    /// Sources of user input that could contain URLs for SSRF attacks
    const JS_SOURCES: &'static [&'static str] = &[
        "req.params",
        "req.query",
        "req.body",
        "request.params",
        "request.query",
        "request.body",
        "req.params.url",
        "req.query.url",
        "req.body.url",
        "req.params.target",
        "req.query.target",
        "req.body.target",
        "req.params.redirect",
        "req.query.redirect",
        "req.body.redirect",
        "req.params.callback",
        "req.query.callback",
        "req.body.callback",
        "req.params.endpoint",
        "req.query.endpoint",
        "req.body.endpoint",
        "req.params.uri",
        "req.query.uri",
        "req.body.uri",
        "req.params.host",
        "req.query.host",
        "req.body.host",
        "req.params.link",
        "req.query.link",
        "req.body.link",
    ];

    const PYTHON_SOURCES: &'static [&'static str] = &[
        "request.args.get('url')",
        "request.args.get('target')",
        "request.args.get('redirect')",
        "request.args.get('callback')",
        "request.args.get('endpoint')",
        "request.args.get('uri')",
        "request.args.get('host')",
        "request.args.get('link')",
        "request.form.get('url')",
        "request.form.get('target')",
        "request.json.get('url')",
        "request.json.get('target')",
        "request.args",
        "request.form",
        "request.json",
        "request.GET.get('url')",
        "request.POST.get('url')",
        "request.GET.get('target')",
        "request.POST.get('target')",
        "request.GET",
        "request.POST",
    ];

    const GO_SOURCES: &'static [&'static str] = &[
        "r.URL.Query().Get(\"url\")",
        "r.URL.Query().Get(\"target\")",
        "r.URL.Query().Get(\"redirect\")",
        "r.URL.Query().Get(\"callback\")",
        "r.FormValue(\"url\")",
        "r.FormValue(\"target\")",
        "r.PostFormValue(\"url\")",
        "r.PostFormValue(\"target\")",
        "r.URL.Query",
        "r.FormValue",
        "r.PostFormValue",
        "c.Query(\"url\")",
        "c.Query(\"target\")",
        "c.Param(\"url\")",
        "c.Param(\"target\")",
        "c.PostForm(\"url\")",
        "c.PostForm(\"target\")",
        "c.Query",
        "c.Param",
        "c.PostForm",
        "c.QueryParam(\"url\")",
        "c.QueryParam(\"target\")",
        "c.FormValue(\"url\")",
        "c.FormValue(\"target\")",
    ];

    const JAVA_SOURCES: &'static [&'static str] = &[
        "request.getParameter(\"url\")",
        "request.getParameter(\"target\")",
        "request.getParameter(\"redirect\")",
        "request.getParameter(\"callback\")",
        "request.getParameter(\"endpoint\")",
        "request.getParameter(\"uri\")",
        "request.getParameter(\"host\")",
        "request.getParameter(\"link\")",
        "request.getParameter",
        "@RequestParam(\"url\")",
        "@RequestParam(\"target\")",
        "@PathVariable(\"url\")",
        "@PathVariable(\"target\")",
        "@RequestParam",
        "@PathVariable",
    ];

    /// Sinks - HTTP client calls where SSRF is dangerous
    const JS_SINKS: &'static [&'static str] = &[
        "fetch",
        "globalThis.fetch",
        "http.get",
        "http.request",
        "https.get",
        "https.request",
        "axios",
        "axios.get",
        "axios.post",
        "axios.put",
        "axios.delete",
        "axios.patch",
        "axios.head",
        "axios.options",
        "axios.request",
        "node-fetch",
        "got",
        "got.get",
        "got.post",
        "got.put",
        "got.delete",
        "request",
        "request.get",
        "request.post",
        "superagent",
        "superagent.get",
        "superagent.post",
        "needle",
        "needle.get",
        "needle.post",
    ];

    const PYTHON_SINKS: &'static [&'static str] = &[
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.delete",
        "requests.patch",
        "requests.head",
        "requests.options",
        "requests.request",
        "urllib.request.urlopen",
        "urllib.request.Request",
        "urllib2.urlopen",
        "urllib2.Request",
        "urlopen",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "HTTPConnection",
        "HTTPSConnection",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.delete",
        "httpx.AsyncClient",
        "httpx.Client",
        "aiohttp.ClientSession",
        "session.get",
        "session.post",
        "httplib2.Http",
        "pycurl.Curl",
    ];

    const GO_SINKS: &'static [&'static str] = &[
        "http.Get",
        "http.Post",
        "http.PostForm",
        "http.Head",
        "http.NewRequest",
        "http.NewRequestWithContext",
        "client.Get",
        "client.Post",
        "client.Do",
        "transport.RoundTrip",
        "resty.R",
        "req.Get",
        "req.Post",
        "fasthttp.Get",
        "fasthttp.Post",
    ];

    const JAVA_SINKS: &'static [&'static str] = &[
        "URL.openConnection",
        "URL.openStream",
        "url.openConnection",
        "url.openStream",
        "new URL",
        "HttpURLConnection",
        "HttpsURLConnection",
        "HttpClient.execute",
        "HttpClients.createDefault",
        "CloseableHttpClient",
        "HttpGet",
        "HttpPost",
        "HttpPut",
        "HttpDelete",
        "OkHttpClient",
        "okHttpClient.newCall",
        "Request.Builder",
        "RestTemplate",
        "restTemplate.getForObject",
        "restTemplate.getForEntity",
        "restTemplate.postForObject",
        "restTemplate.postForEntity",
        "restTemplate.exchange",
        "WebClient",
        "webClient.get",
        "webClient.post",
        "Client",
        "client.target",
    ];

    fn is_ssrf_source(&self, expr: &str, language: Language) -> bool {
        let sources = match language {
            Language::JavaScript | Language::TypeScript => Self::JS_SOURCES,
            Language::Python => Self::PYTHON_SOURCES,
            Language::Go => Self::GO_SOURCES,
            Language::Java => Self::JAVA_SOURCES,
            _ => return false,
        };
        let expr_lower = expr.to_lowercase();
        sources.iter().any(|src| {
            let src_lower = src.to_lowercase();
            expr_lower.contains(&src_lower) || src_lower.contains(&expr_lower)
        })
    }

    fn is_http_sink(&self, func_name: &str, language: Language) -> bool {
        let sinks = match language {
            Language::JavaScript | Language::TypeScript => Self::JS_SINKS,
            Language::Python => Self::PYTHON_SINKS,
            Language::Go => Self::GO_SINKS,
            Language::Java => Self::JAVA_SINKS,
            _ => return false,
        };
        let func_lower = func_name.to_lowercase();
        sinks.iter().any(|sink| {
            let sink_lower = sink.to_lowercase();
            func_lower.contains(&sink_lower) || func_lower.ends_with(&sink_lower)
        })
    }

    fn is_safe_url_literal(url: &str) -> bool {
        let url_lower = url.to_lowercase();
        if !url_lower.starts_with("http://") && !url_lower.starts_with("https://") {
            return false;
        }
        for pattern in PRIVATE_IP_PATTERNS.iter() {
            if url_lower.contains(pattern) {
                return false;
            }
        }
        true
    }

    fn is_url_variable(&self, var_name: &str) -> bool {
        let var_lower = var_name.to_lowercase();
        var_lower.contains("url")
            || var_lower.contains("uri")
            || var_lower.contains("target")
            || var_lower.contains("redirect")
            || var_lower.contains("callback")
            || var_lower.contains("endpoint")
            || var_lower.contains("host")
            || var_lower.contains("link")
            || var_lower.contains("href")
            || var_lower.contains("src")
            || var_lower.contains("dest")
            || var_lower.contains("destination")
    }

    fn get_suggestion(&self, language: Language) -> &'static str {
        match language {
            Language::JavaScript | Language::TypeScript => {
                "Validate URLs against an allowlist of trusted domains. Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). Only allow http/https schemes."
            }
            Language::Python => {
                "Use the ipaddress module to validate IPs are not private. Validate URLs against an allowlist. Block schemes other than http/https. Use urllib.parse.urlparse() to validate hostnames."
            }
            Language::Go => {
                "Use net.ParseIP() to check if resolved IP is not in private ranges. Validate URL scheme is http/https. Use url.Parse() to extract and validate hostname against an allowlist."
            }
            Language::Java => {
                "Use InetAddress methods (isLoopbackAddress, isSiteLocalAddress, isLinkLocalAddress) to block private IPs. Validate URLs against an allowlist. Use URI.getHost() to validate hostnames."
            }
            _ => {
                "Validate URLs against an allowlist. Block private IP ranges and non-http(s) schemes."
            }
        }
    }
}

impl Rule for SsrfTaintRule {
    fn id(&self) -> &str {
        "security/ssrf-taint"
    }
    fn description(&self) -> &str {
        "Detects SSRF vulnerabilities where user-controlled URLs flow to HTTP clients"
    }

    fn applies_to(&self, lang: Language) -> bool {
        matches!(
            lang,
            Language::JavaScript
                | Language::TypeScript
                | Language::Python
                | Language::Go
                | Language::Java
        )
    }

    fn check(&self, _parsed: &ParsedFile) -> Vec<Finding> {
        Vec::new()
    }

    fn check_with_flow(&self, parsed: &ParsedFile, flow: &FlowContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        if super::generic::is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        if let Some(interproc) = flow.interprocedural_result() {
            // Check for URL-specific taint flows
            for taint_flow in interproc.flows_by_kind(TaintKind::Url) {
                if self.is_http_sink(&taint_flow.sink.name, parsed.language) {
                    let message = format!(
                        "SSRF vulnerability: user-controlled URL '{}' (line {}) flows to HTTP client '{}' (line {}). {}",
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        self.get_suggestion(parsed.language)
                    );
                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        taint_flow.sink.line,
                        &taint_flow.sink.name,
                        Severity::Error,
                        &message,
                        parsed.language,
                    );
                    finding.confidence = Confidence::High;
                    finding.suggestion = Some(self.get_suggestion(parsed.language).to_string());
                    findings.push(finding);
                }
            }

            // Check UserInput flows reaching HTTP sinks
            for taint_flow in interproc.flows_by_kind(TaintKind::UserInput) {
                if self.is_http_sink(&taint_flow.sink.name, parsed.language) {
                    let message = format!(
                        "Potential SSRF: user input '{}' (line {}) may flow to HTTP client '{}' (line {}). {}",
                        taint_flow.source.name,
                        taint_flow.source.line,
                        taint_flow.sink.name,
                        taint_flow.sink.line,
                        self.get_suggestion(parsed.language)
                    );
                    let mut finding = create_finding_at_line(
                        self.id(),
                        &parsed.path,
                        taint_flow.sink.line,
                        &taint_flow.sink.name,
                        Severity::Warning,
                        &message,
                        parsed.language,
                    );
                    finding.confidence = Confidence::Medium;
                    finding.suggestion = Some(self.get_suggestion(parsed.language).to_string());
                    findings.push(finding);
                }
            }
        }

        // Check symbol table for tainted URL variables
        for (var_name, _info) in flow.symbols.iter() {
            if !flow.is_tainted(var_name) {
                continue;
            }
            let is_url_var = self.is_url_variable(var_name);
            if is_url_var && self.is_ssrf_source(var_name, parsed.language) {
                if let Some(interproc) = flow.interprocedural_result() {
                    for call_site in &interproc.call_sites {
                        if self.is_http_sink(&call_site.callee_name, parsed.language) {
                            for arg in &call_site.arguments {
                                let uses_tainted =
                                    arg.var_name.as_ref().is_some_and(|n| n == var_name)
                                        || arg.expr.contains(var_name);
                                if uses_tainted && !Self::is_safe_url_literal(&arg.expr) {
                                    let message = format!(
                                        "SSRF risk: tainted URL variable '{}' used in HTTP client '{}' on line {}. {}",
                                        var_name,
                                        call_site.callee_name,
                                        call_site.line,
                                        self.get_suggestion(parsed.language)
                                    );
                                    let mut finding = create_finding_at_line(
                                        self.id(),
                                        &parsed.path,
                                        call_site.line,
                                        &call_site.callee_name,
                                        Severity::Warning,
                                        &message,
                                        parsed.language,
                                    );
                                    finding.confidence = Confidence::Medium;
                                    finding.suggestion =
                                        Some(self.get_suggestion(parsed.language).to_string());
                                    findings.push(finding);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check HTTP calls with variable URLs and taint levels
        if let Some(interproc) = flow.interprocedural_result() {
            for call_site in &interproc.call_sites {
                if self.is_http_sink(&call_site.callee_name, parsed.language) {
                    if let Some(first_arg) = call_site.arguments.first() {
                        if let Some(ref var_name) = first_arg.var_name {
                            let taint_level = flow.taint_level_at(var_name, call_site.node_id);
                            match taint_level {
                                TaintLevel::Full => {
                                    let message = format!(
                                        "SSRF vulnerability: variable '{}' used as URL in '{}' is tainted. {}",
                                        var_name,
                                        call_site.callee_name,
                                        self.get_suggestion(parsed.language)
                                    );
                                    let mut finding = create_finding_at_line(
                                        self.id(),
                                        &parsed.path,
                                        call_site.line,
                                        &call_site.callee_name,
                                        Severity::Error,
                                        &message,
                                        parsed.language,
                                    );
                                    finding.confidence = Confidence::High;
                                    finding.suggestion =
                                        Some(self.get_suggestion(parsed.language).to_string());
                                    findings.push(finding);
                                }
                                TaintLevel::Partial => {
                                    let message = format!(
                                        "Potential SSRF: variable '{}' used as URL in '{}' may be tainted on some paths. {}",
                                        var_name,
                                        call_site.callee_name,
                                        self.get_suggestion(parsed.language)
                                    );
                                    let mut finding = create_finding_at_line(
                                        self.id(),
                                        &parsed.path,
                                        call_site.line,
                                        &call_site.callee_name,
                                        Severity::Warning,
                                        &message,
                                        parsed.language,
                                    );
                                    finding.confidence = Confidence::Medium;
                                    finding.suggestion =
                                        Some(self.get_suggestion(parsed.language).to_string());
                                    findings.push(finding);
                                }
                                TaintLevel::Clean => {
                                    if self.is_url_variable(var_name) {
                                        let message = format!(
                                            "SSRF review: URL variable '{}' used in HTTP client '{}'. Verify URL cannot be user-controlled. {}",
                                            var_name,
                                            call_site.callee_name,
                                            self.get_suggestion(parsed.language)
                                        );
                                        let mut finding = create_finding_at_line(
                                            self.id(),
                                            &parsed.path,
                                            call_site.line,
                                            &call_site.callee_name,
                                            Severity::Info,
                                            &message,
                                            parsed.language,
                                        );
                                        finding.confidence = Confidence::Low;
                                        finding.suggestion =
                                            Some(self.get_suggestion(parsed.language).to_string());
                                        findings.push(finding);
                                    }
                                }
                            }
                        } else if !first_arg.expr.starts_with('"')
                            && !first_arg.expr.starts_with('\'')
                        {
                            for pattern in PRIVATE_IP_PATTERNS.iter() {
                                if first_arg.expr.contains(pattern) {
                                    let message = format!(
                                        "Suspicious SSRF: HTTP request contains internal address pattern '{}' in '{}'. {}",
                                        pattern,
                                        call_site.callee_name,
                                        self.get_suggestion(parsed.language)
                                    );
                                    let mut finding = create_finding_at_line(
                                        self.id(),
                                        &parsed.path,
                                        call_site.line,
                                        &call_site.callee_name,
                                        Severity::Warning,
                                        &message,
                                        parsed.language,
                                    );
                                    finding.confidence = Confidence::Medium;
                                    finding.suggestion =
                                        Some(self.get_suggestion(parsed.language).to_string());
                                    findings.push(finding);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        findings.sort_by_key(|f| (f.location.start_line, f.location.start_column));
        findings.dedup_by(|a, b| {
            a.location.start_line == b.location.start_line
                && a.location.start_column == b.location.start_column
        });
        findings
    }

    fn uses_flow(&self) -> bool {
        true
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Variables that are commonly unused intentionally
fn should_skip_variable(name: &str) -> bool {
    // Underscore-prefixed variables are intentionally unused
    if name.starts_with('_') {
        return true;
    }

    // Common intentionally unused names
    let skip_names = [
        "unused", "ignore", "ignored", "dummy", "temp", "tmp", "_", "__", "err",
    ];
    if skip_names.contains(&name) {
        return true;
    }

    // Very short names are often intentional placeholders
    if name.len() == 1 && name.chars().next().map_or(false, |c| c.is_lowercase()) {
        // Skip single lowercase letters except for common meaningful ones
        let meaningful = ['i', 'j', 'k', 'n', 'x', 'y', 'z'];
        if !meaningful.contains(&name.chars().next().unwrap()) {
            return true;
        }
    }

    false
}

/// Check if a name is likely a global/builtin
fn is_likely_global(name: &str) -> bool {
    // JavaScript/TypeScript globals
    let js_globals = [
        "console",
        "window",
        "document",
        "process",
        "global",
        "require",
        "module",
        "exports",
        "Buffer",
        "setTimeout",
        "setInterval",
        "clearTimeout",
        "clearInterval",
        "Promise",
        "fetch",
        "JSON",
        "Math",
        "Object",
        "Array",
        "String",
        "Number",
        "Boolean",
        "Date",
        "Error",
        "undefined",
        "null",
        "NaN",
        "Infinity",
    ];

    // Python builtins
    let py_builtins = [
        "print",
        "len",
        "range",
        "str",
        "int",
        "float",
        "list",
        "dict",
        "set",
        "tuple",
        "open",
        "True",
        "False",
        "None",
        "type",
        "isinstance",
        "hasattr",
        "getattr",
        "setattr",
        "super",
        "self",
        "cls",
    ];

    js_globals.contains(&name) || py_builtins.contains(&name)
}

/// Get all dataflow-powered rules
pub fn dataflow_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(DeadStoreRule),
        Box::new(UnusedVariableRule),
        Box::new(CrossFunctionTaintRule),
        Box::new(UninitializedVariableRule),
        Box::new(super::null_pointer::NullPointerRule),
        Box::new(PathTraversalTaintRule),
        Box::new(CommandInjectionTaintRule),
        Box::new(SqlInjectionTaintRule),
        Box::new(SsrfTaintRule),
        Box::new(super::xss_taint::XssDetectionRule::new()),
        Box::new(super::resource_leak::ResourceLeakRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_underscore_variables() {
        assert!(should_skip_variable("_"));
        assert!(should_skip_variable("_unused"));
        assert!(should_skip_variable("__"));
        assert!(!should_skip_variable("x"));
        assert!(!should_skip_variable("data"));
    }

    #[test]
    fn test_skip_common_unused_names() {
        assert!(should_skip_variable("unused"));
        assert!(should_skip_variable("ignore"));
        assert!(should_skip_variable("dummy"));
        assert!(should_skip_variable("err")); // Common Go pattern
    }

    #[test]
    fn test_is_likely_global() {
        assert!(is_likely_global("console"));
        assert!(is_likely_global("window"));
        assert!(is_likely_global("print"));
        assert!(is_likely_global("len"));
        assert!(!is_likely_global("myVariable"));
        assert!(!is_likely_global("userData"));
    }

    #[test]
    fn test_rules_implement_trait() {
        let rules = dataflow_rules();
        assert!(!rules.is_empty());

        for rule in &rules {
            assert!(!rule.id().is_empty());
            assert!(!rule.description().is_empty());
            assert!(rule.uses_flow());
        }
    }

    // =========================================================================
    // Path Traversal Rule Tests
    // =========================================================================

    #[test]
    fn test_path_traversal_rule_applies_to_languages() {
        let rule = PathTraversalTaintRule;
        assert!(rule.applies_to(Language::JavaScript));
        assert!(rule.applies_to(Language::TypeScript));
        assert!(rule.applies_to(Language::Python));
        assert!(rule.applies_to(Language::Go));
        assert!(rule.applies_to(Language::Java));
        assert!(!rule.applies_to(Language::Rust));
    }

    #[test]
    fn test_path_traversal_js_sources() {
        let rule = PathTraversalTaintRule;
        assert!(rule.is_path_source("req.params", Language::JavaScript));
        assert!(rule.is_path_source("req.query.filename", Language::JavaScript));
        assert!(rule.is_path_source("request.body", Language::JavaScript));
        assert!(!rule.is_path_source("console.log", Language::JavaScript));
    }

    #[test]
    fn test_path_traversal_python_sources() {
        let rule = PathTraversalTaintRule;
        assert!(rule.is_path_source("request.args", Language::Python));
        assert!(rule.is_path_source("request.form", Language::Python));
        assert!(rule.is_path_source("request.files", Language::Python));
        assert!(!rule.is_path_source("print", Language::Python));
    }

    #[test]
    fn test_path_traversal_go_sources() {
        let rule = PathTraversalTaintRule;
        assert!(rule.is_path_source("r.URL.Query", Language::Go));
        assert!(rule.is_path_source("r.FormValue", Language::Go));
        assert!(rule.is_path_source("c.Param", Language::Go));
        assert!(!rule.is_path_source("fmt.Println", Language::Go));
    }

    #[test]
    fn test_path_traversal_java_sources() {
        let rule = PathTraversalTaintRule;
        assert!(rule.is_path_source("request.getParameter", Language::Java));
        assert!(rule.is_path_source("@PathVariable", Language::Java));
        assert!(!rule.is_path_source("System.out", Language::Java));
    }

    #[test]
    fn test_path_traversal_js_sinks() {
        let rule = PathTraversalTaintRule;
        assert!(rule.is_path_sink("fs.readFile", Language::JavaScript));
        assert!(rule.is_path_sink("fs.writeFileSync", Language::JavaScript));
        assert!(rule.is_path_sink("path.join", Language::JavaScript));
        assert!(rule.is_path_sink("require", Language::JavaScript));
        assert!(!rule.is_path_sink("console.log", Language::JavaScript));
    }

    #[test]
    fn test_path_traversal_python_sinks() {
        let rule = PathTraversalTaintRule;
        assert!(rule.is_path_sink("open", Language::Python));
        assert!(rule.is_path_sink("os.path.join", Language::Python));
        assert!(rule.is_path_sink("pathlib.Path", Language::Python));
        assert!(rule.is_path_sink("send_file", Language::Python));
        assert!(!rule.is_path_sink("print", Language::Python));
    }

    #[test]
    fn test_path_traversal_go_sinks() {
        let rule = PathTraversalTaintRule;
        assert!(rule.is_path_sink("os.Open", Language::Go));
        assert!(rule.is_path_sink("ioutil.ReadFile", Language::Go));
        assert!(rule.is_path_sink("filepath.Join", Language::Go));
        assert!(rule.is_path_sink("http.ServeFile", Language::Go));
        assert!(!rule.is_path_sink("fmt.Println", Language::Go));
    }

    #[test]
    fn test_path_traversal_java_sinks() {
        let rule = PathTraversalTaintRule;
        assert!(rule.is_path_sink("new File", Language::Java));
        assert!(rule.is_path_sink("FileInputStream", Language::Java));
        assert!(rule.is_path_sink("Files.readAllBytes", Language::Java));
        assert!(rule.is_path_sink("Paths.get", Language::Java));
        assert!(!rule.is_path_sink("System.out.println", Language::Java));
    }

    #[test]
    fn test_path_traversal_suggestions() {
        let rule = PathTraversalTaintRule;

        let js_suggestion = rule.get_suggestion(Language::JavaScript);
        assert!(js_suggestion.contains("path.basename"));
        assert!(js_suggestion.contains("startsWith"));

        let py_suggestion = rule.get_suggestion(Language::Python);
        assert!(py_suggestion.contains("os.path.basename"));
        assert!(py_suggestion.contains("os.path.realpath"));

        let go_suggestion = rule.get_suggestion(Language::Go);
        assert!(go_suggestion.contains("filepath.Base"));
        assert!(go_suggestion.contains("HasPrefix"));

        let java_suggestion = rule.get_suggestion(Language::Java);
        assert!(java_suggestion.contains("getCanonicalPath"));
        assert!(java_suggestion.contains("FilenameUtils"));
    }

    // =============================================================================
    // SQL Injection Taint Rule Tests
    // =============================================================================

    #[test]
    fn test_sql_injection_js_sinks() {
        let rule = SqlInjectionTaintRule;
        assert!(rule.is_sql_sink("db.query", Language::JavaScript));
        assert!(rule.is_sql_sink("connection.execute", Language::JavaScript));
        assert!(rule.is_sql_sink("mysql.query", Language::JavaScript));
        assert!(rule.is_sql_sink("pool.query", Language::JavaScript));
        assert!(rule.is_sql_sink("$queryRaw", Language::JavaScript));
        assert!(rule.is_sql_sink("knex.raw", Language::JavaScript));
        assert!(!rule.is_sql_sink("console.log", Language::JavaScript));
    }

    #[test]
    fn test_sql_injection_python_sinks() {
        let rule = SqlInjectionTaintRule;
        assert!(rule.is_sql_sink("cursor.execute", Language::Python));
        assert!(rule.is_sql_sink("cursor.executemany", Language::Python));
        assert!(rule.is_sql_sink("session.execute", Language::Python));
        assert!(rule.is_sql_sink("connection.execute", Language::Python));
        assert!(rule.is_sql_sink("db.execute", Language::Python));
        assert!(!rule.is_sql_sink("print", Language::Python));
    }

    #[test]
    fn test_sql_injection_go_sinks() {
        let rule = SqlInjectionTaintRule;
        assert!(rule.is_sql_sink("db.Query", Language::Go));
        assert!(rule.is_sql_sink("db.QueryRow", Language::Go));
        assert!(rule.is_sql_sink("db.Exec", Language::Go));
        assert!(rule.is_sql_sink("tx.Query", Language::Go));
        assert!(rule.is_sql_sink("db.Raw", Language::Go));
        assert!(!rule.is_sql_sink("fmt.Println", Language::Go));
    }

    #[test]
    fn test_sql_injection_java_sinks() {
        let rule = SqlInjectionTaintRule;
        assert!(rule.is_sql_sink("Statement.executeQuery", Language::Java));
        assert!(rule.is_sql_sink("Statement.executeUpdate", Language::Java));
        assert!(rule.is_sql_sink("PreparedStatement.execute", Language::Java));
        assert!(rule.is_sql_sink("session.createQuery", Language::Java));
        assert!(rule.is_sql_sink("jdbcTemplate.query", Language::Java));
        assert!(!rule.is_sql_sink("System.out.println", Language::Java));
    }

    #[test]
    fn test_parameterized_query_detection() {
        // Question mark placeholders (MySQL, SQLite, etc.)
        assert!(SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users WHERE id = ?"
        ));
        assert!(SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users WHERE id = ? AND name = ?"
        ));

        // PostgreSQL positional parameters
        assert!(SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users WHERE id = $1"
        ));
        assert!(SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users WHERE id = $1 AND name = $2"
        ));

        // Named parameters (SQLAlchemy style)
        assert!(SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users WHERE id = :user_id"
        ));
        assert!(SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users WHERE id = :id AND name = :name"
        ));

        // SQL Server style parameters
        assert!(SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users WHERE id = @userId"
        ));

        // Python DB-API placeholders
        assert!(SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users WHERE id = %s"
        ));
        assert!(SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users WHERE id = %(user_id)s"
        ));

        // Non-parameterized queries (vulnerable)
        assert!(!SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users WHERE id = 1"
        ));
        assert!(!SqlInjectionTaintRule::is_parameterized_query(
            "SELECT * FROM users"
        ));
    }

    #[test]
    fn test_sql_injection_suggestions() {
        let rule = SqlInjectionTaintRule;

        let js_suggestion = rule.get_suggestion(Language::JavaScript);
        assert!(js_suggestion.contains("parameterized"));
        assert!(js_suggestion.contains("?"));

        let py_suggestion = rule.get_suggestion(Language::Python);
        assert!(py_suggestion.contains("parameterized"));
        assert!(py_suggestion.contains("%s"));

        let go_suggestion = rule.get_suggestion(Language::Go);
        assert!(go_suggestion.contains("parameterized"));
        assert!(go_suggestion.contains("$1"));

        let java_suggestion = rule.get_suggestion(Language::Java);
        assert!(java_suggestion.contains("PreparedStatement"));
        assert!(java_suggestion.contains("?"));
    }

    // =========================================================================
    // Command Injection Taint Rule Tests
    // =========================================================================

    #[test]
    fn test_command_injection_rule_applies_to_languages() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.applies_to(Language::JavaScript));
        assert!(rule.applies_to(Language::TypeScript));
        assert!(rule.applies_to(Language::Python));
        assert!(rule.applies_to(Language::Go));
        assert!(rule.applies_to(Language::Rust));
        assert!(rule.applies_to(Language::Java));
    }

    #[test]
    fn test_command_injection_js_sources() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.is_command_source("req.query", Language::JavaScript));
        assert!(rule.is_command_source("req.body", Language::JavaScript));
        assert!(rule.is_command_source("process.argv", Language::JavaScript));
        assert!(rule.is_command_source("process.env", Language::JavaScript));
        assert!(!rule.is_command_source("console.log", Language::JavaScript));
    }

    #[test]
    fn test_command_injection_python_sources() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.is_command_source("request.args", Language::Python));
        assert!(rule.is_command_source("sys.argv", Language::Python));
        assert!(rule.is_command_source("os.environ", Language::Python));
        assert!(rule.is_command_source("input", Language::Python));
        assert!(!rule.is_command_source("print", Language::Python));
    }

    #[test]
    fn test_command_injection_go_sources() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.is_command_source("r.URL.Query", Language::Go));
        assert!(rule.is_command_source("os.Args", Language::Go));
        assert!(rule.is_command_source("os.Getenv", Language::Go));
        assert!(!rule.is_command_source("fmt.Println", Language::Go));
    }

    #[test]
    fn test_command_injection_rust_sources() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.is_command_source("std::env::args", Language::Rust));
        assert!(rule.is_command_source("env::var", Language::Rust));
        assert!(rule.is_command_source("io::stdin", Language::Rust));
        assert!(!rule.is_command_source("println", Language::Rust));
    }

    #[test]
    fn test_command_injection_java_sources() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.is_command_source("request.getParameter", Language::Java));
        assert!(rule.is_command_source("System.getenv", Language::Java));
        assert!(rule.is_command_source("Scanner", Language::Java));
        assert!(!rule.is_command_source("System.out", Language::Java));
    }

    #[test]
    fn test_command_injection_js_sinks() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.is_command_sink("child_process.exec", Language::JavaScript));
        assert!(rule.is_command_sink("child_process.spawn", Language::JavaScript));
        assert!(rule.is_command_sink("execa", Language::JavaScript));
        assert!(!rule.is_command_sink("console.log", Language::JavaScript));
    }

    #[test]
    fn test_command_injection_python_sinks() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.is_command_sink("subprocess.call", Language::Python));
        assert!(rule.is_command_sink("subprocess.run", Language::Python));
        assert!(rule.is_command_sink("subprocess.Popen", Language::Python));
        assert!(rule.is_command_sink("os.system", Language::Python));
        assert!(rule.is_command_sink("os.popen", Language::Python));
        assert!(!rule.is_command_sink("print", Language::Python));
    }

    #[test]
    fn test_command_injection_go_sinks() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.is_command_sink("exec.Command", Language::Go));
        assert!(rule.is_command_sink("exec.CommandContext", Language::Go));
        assert!(rule.is_command_sink("os.StartProcess", Language::Go));
        assert!(!rule.is_command_sink("fmt.Println", Language::Go));
    }

    #[test]
    fn test_command_injection_rust_sinks() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.is_command_sink("Command::new", Language::Rust));
        assert!(rule.is_command_sink("std::process::Command::new", Language::Rust));
        assert!(rule.is_command_sink("tokio::process::Command::new", Language::Rust));
        assert!(!rule.is_command_sink("println", Language::Rust));
    }

    #[test]
    fn test_command_injection_java_sinks() {
        let rule = CommandInjectionTaintRule;
        assert!(rule.is_command_sink("Runtime.getRuntime", Language::Java));
        assert!(rule.is_command_sink("ProcessBuilder", Language::Java));
        assert!(!rule.is_command_sink("System.out.println", Language::Java));
    }

    #[test]
    fn test_shell_mode_detection() {
        let rule = CommandInjectionTaintRule;
        // Python shell=True
        assert!(rule.has_shell_mode("subprocess.call(cmd, shell=True)"));
        assert!(rule.has_shell_mode("subprocess.run(cmd, shell = True)"));
        // Node.js shell option
        assert!(rule.has_shell_mode("spawn(cmd, { shell: true })"));
        // Shell invocations
        assert!(rule.has_shell_mode("sh -c"));
        assert!(rule.has_shell_mode("bash -c"));
        assert!(rule.has_shell_mode("/bin/sh"));
        assert!(rule.has_shell_mode("/bin/bash"));
        // Non-shell mode
        assert!(!rule.has_shell_mode("subprocess.call(['ls', '-l'])"));
        assert!(!rule.has_shell_mode("spawn('ls', ['-l'])"));
    }

    #[test]
    fn test_command_injection_severity() {
        let rule = CommandInjectionTaintRule;
        // Shell mode = Error (Critical)
        assert_eq!(rule.determine_severity(true), Severity::Error);
        // Non-shell mode = Warning (still dangerous)
        assert_eq!(rule.determine_severity(false), Severity::Warning);
    }

    #[test]
    fn test_command_injection_suggestions() {
        let rule = CommandInjectionTaintRule;

        // JavaScript - shell mode
        let js_shell = rule.get_suggestion(Language::JavaScript, true);
        assert!(js_shell.contains("CRITICAL"));
        assert!(js_shell.contains("execFile") || js_shell.contains("spawn"));

        // JavaScript - non-shell mode
        let js_no_shell = rule.get_suggestion(Language::JavaScript, false);
        assert!(js_no_shell.contains("array"));

        // Python - shell mode
        let py_shell = rule.get_suggestion(Language::Python, true);
        assert!(py_shell.contains("CRITICAL"));
        assert!(py_shell.contains("shlex.quote"));

        // Python - non-shell mode
        let py_no_shell = rule.get_suggestion(Language::Python, false);
        assert!(py_no_shell.contains("list"));

        // Go
        let go_suggestion = rule.get_suggestion(Language::Go, false);
        assert!(go_suggestion.contains("exec.Command"));

        // Rust
        let rust_suggestion = rule.get_suggestion(Language::Rust, false);
        assert!(rust_suggestion.contains("Command::new"));
        assert!(rust_suggestion.contains("arg"));

        // Java - shell mode
        let java_shell = rule.get_suggestion(Language::Java, true);
        assert!(java_shell.contains("CRITICAL"));
        assert!(java_shell.contains("ProcessBuilder"));
    }

    // =========================================================================
    // SSRF Taint Rule Tests
    // =========================================================================

    #[test]
    fn test_ssrf_rule_applies_to_languages() {
        let rule = SsrfTaintRule;
        assert!(rule.applies_to(Language::JavaScript));
        assert!(rule.applies_to(Language::TypeScript));
        assert!(rule.applies_to(Language::Python));
        assert!(rule.applies_to(Language::Go));
        assert!(rule.applies_to(Language::Java));
        assert!(!rule.applies_to(Language::Rust));
    }

    #[test]
    fn test_ssrf_js_sources() {
        let rule = SsrfTaintRule;
        assert!(rule.is_ssrf_source("req.query.url", Language::JavaScript));
        assert!(rule.is_ssrf_source("req.body.target", Language::JavaScript));
        assert!(rule.is_ssrf_source("req.params.redirect", Language::JavaScript));
        assert!(rule.is_ssrf_source("request.query", Language::JavaScript));
        assert!(!rule.is_ssrf_source("console.log", Language::JavaScript));
    }

    #[test]
    fn test_ssrf_python_sources() {
        let rule = SsrfTaintRule;
        assert!(rule.is_ssrf_source("request.args.get('url')", Language::Python));
        assert!(rule.is_ssrf_source("request.form.get('target')", Language::Python));
        assert!(rule.is_ssrf_source("request.json", Language::Python));
        assert!(rule.is_ssrf_source("request.GET", Language::Python));
        assert!(!rule.is_ssrf_source("print", Language::Python));
    }

    #[test]
    fn test_ssrf_go_sources() {
        let rule = SsrfTaintRule;
        assert!(rule.is_ssrf_source("r.FormValue(\"url\")", Language::Go));
        assert!(rule.is_ssrf_source("r.URL.Query", Language::Go));
        assert!(rule.is_ssrf_source("c.Query(\"target\")", Language::Go));
        assert!(rule.is_ssrf_source("c.Param", Language::Go));
        assert!(!rule.is_ssrf_source("fmt.Println", Language::Go));
    }

    #[test]
    fn test_ssrf_java_sources() {
        let rule = SsrfTaintRule;
        assert!(rule.is_ssrf_source("request.getParameter(\"url\")", Language::Java));
        assert!(rule.is_ssrf_source("request.getParameter", Language::Java));
        assert!(rule.is_ssrf_source("@RequestParam(\"target\")", Language::Java));
        assert!(rule.is_ssrf_source("@PathVariable", Language::Java));
        assert!(!rule.is_ssrf_source("System.out", Language::Java));
    }

    #[test]
    fn test_ssrf_js_sinks() {
        let rule = SsrfTaintRule;
        assert!(rule.is_http_sink("fetch", Language::JavaScript));
        assert!(rule.is_http_sink("axios.get", Language::JavaScript));
        assert!(rule.is_http_sink("http.request", Language::JavaScript));
        assert!(rule.is_http_sink("got.post", Language::JavaScript));
        assert!(rule.is_http_sink("request.get", Language::JavaScript));
        assert!(!rule.is_http_sink("console.log", Language::JavaScript));
    }

    #[test]
    fn test_ssrf_python_sinks() {
        let rule = SsrfTaintRule;
        assert!(rule.is_http_sink("requests.get", Language::Python));
        assert!(rule.is_http_sink("requests.post", Language::Python));
        assert!(rule.is_http_sink("urllib.request.urlopen", Language::Python));
        assert!(rule.is_http_sink("httpx.get", Language::Python));
        assert!(rule.is_http_sink("aiohttp.ClientSession", Language::Python));
        assert!(!rule.is_http_sink("print", Language::Python));
    }

    #[test]
    fn test_ssrf_go_sinks() {
        let rule = SsrfTaintRule;
        assert!(rule.is_http_sink("http.Get", Language::Go));
        assert!(rule.is_http_sink("http.Post", Language::Go));
        assert!(rule.is_http_sink("http.NewRequest", Language::Go));
        assert!(rule.is_http_sink("client.Do", Language::Go));
        assert!(rule.is_http_sink("resty.R", Language::Go));
        assert!(!rule.is_http_sink("fmt.Println", Language::Go));
    }

    #[test]
    fn test_ssrf_java_sinks() {
        let rule = SsrfTaintRule;
        assert!(rule.is_http_sink("URL.openConnection", Language::Java));
        assert!(rule.is_http_sink("HttpClient.execute", Language::Java));
        assert!(rule.is_http_sink("RestTemplate", Language::Java));
        assert!(rule.is_http_sink("restTemplate.getForObject", Language::Java));
        assert!(rule.is_http_sink("WebClient", Language::Java));
        assert!(rule.is_http_sink("OkHttpClient", Language::Java));
        assert!(!rule.is_http_sink("System.out.println", Language::Java));
    }

    #[test]
    fn test_ssrf_url_variable_detection() {
        let rule = SsrfTaintRule;
        assert!(rule.is_url_variable("targetUrl"));
        assert!(rule.is_url_variable("redirectUri"));
        assert!(rule.is_url_variable("callbackUrl"));
        assert!(rule.is_url_variable("endpointUrl"));
        assert!(rule.is_url_variable("hostAddress"));
        assert!(rule.is_url_variable("srcLink"));
        assert!(rule.is_url_variable("destination"));
        assert!(!rule.is_url_variable("userName"));
        assert!(!rule.is_url_variable("count"));
    }

    #[test]
    fn test_ssrf_safe_url_literal() {
        // Safe URLs
        assert!(SsrfTaintRule::is_safe_url_literal(
            "https://api.example.com/data"
        ));
        assert!(SsrfTaintRule::is_safe_url_literal(
            "http://external-service.com/webhook"
        ));

        // Unsafe - private IPs
        assert!(!SsrfTaintRule::is_safe_url_literal(
            "http://127.0.0.1/admin"
        ));
        assert!(!SsrfTaintRule::is_safe_url_literal(
            "http://10.0.0.1/internal"
        ));
        assert!(!SsrfTaintRule::is_safe_url_literal(
            "http://192.168.1.1/config"
        ));
        assert!(!SsrfTaintRule::is_safe_url_literal("http://172.16.0.1/api"));
        assert!(!SsrfTaintRule::is_safe_url_literal(
            "http://localhost/secret"
        ));

        // Unsafe - metadata endpoints
        assert!(!SsrfTaintRule::is_safe_url_literal(
            "http://169.254.169.254/latest/meta-data"
        ));
        assert!(!SsrfTaintRule::is_safe_url_literal(
            "http://metadata.google.internal/"
        ));

        // Unsafe - non-http schemes
        assert!(!SsrfTaintRule::is_safe_url_literal("file:///etc/passwd"));
        assert!(!SsrfTaintRule::is_safe_url_literal("gopher://internal/"));
    }

    #[test]
    fn test_ssrf_private_ip_patterns() {
        // Verify private IP patterns are loaded
        assert!(PRIVATE_IP_PATTERNS.contains(&"127."));
        assert!(PRIVATE_IP_PATTERNS.contains(&"10."));
        assert!(PRIVATE_IP_PATTERNS.contains(&"192.168."));
        assert!(PRIVATE_IP_PATTERNS.contains(&"169.254.169.254"));
        assert!(PRIVATE_IP_PATTERNS.contains(&"localhost"));
        assert!(PRIVATE_IP_PATTERNS.contains(&"metadata"));
    }

    #[test]
    fn test_ssrf_suggestions() {
        let rule = SsrfTaintRule;

        let js_suggestion = rule.get_suggestion(Language::JavaScript);
        assert!(js_suggestion.contains("allowlist"));
        assert!(js_suggestion.contains("private IP"));

        let py_suggestion = rule.get_suggestion(Language::Python);
        assert!(py_suggestion.contains("ipaddress"));
        assert!(py_suggestion.contains("urlparse"));

        let go_suggestion = rule.get_suggestion(Language::Go);
        assert!(go_suggestion.contains("net.ParseIP"));
        assert!(go_suggestion.contains("url.Parse"));

        let java_suggestion = rule.get_suggestion(Language::Java);
        assert!(java_suggestion.contains("InetAddress"));
        assert!(java_suggestion.contains("isLoopbackAddress"));
    }
}
