//! Python-specific security vulnerability DETECTION rules
//!
//! This module contains STATIC ANALYSIS rules that scan Python source code
//! to identify potential security vulnerabilities. It does NOT execute any code.

use crate::rules::{Rule, create_finding, create_finding_with_confidence};
use crate::security::generic::is_test_or_fixture_file;
use rma_common::{Confidence, Finding, Language, Severity};
use rma_parser::ParsedFile;
use tree_sitter::Node;

/// DETECTS dangerous dynamic code execution patterns via AST scanning
pub struct DynamicExecutionRule;

impl Rule for DynamicExecutionRule {
    fn id(&self) -> &str {
        "python/dynamic-execution"
    }

    fn description(&self) -> &str {
        "Scans AST to detect dangerous dynamic code execution patterns"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Static list of function names to flag during AST analysis
        let flagged_builtins = ["exec", "compile", "__import__"];

        find_calls(&mut cursor, |node: Node| {
            if let Some(func) = node.child_by_field_name("function")
                && let Ok(text) = func.utf8_text(parsed.content.as_bytes())
                && flagged_builtins.contains(&text)
            {
                findings.push(create_finding(
                    self.id(),
                    &node,
                    &parsed.path,
                    &parsed.content,
                    Severity::Critical,
                    &format!(
                        "AST detected {} call - review for code injection risk",
                        text
                    ),
                    Language::Python,
                ));
            }
        });
        findings
    }
}

/// DETECTS potential shell command injection via static pattern matching
pub struct ShellInjectionRule;

impl Rule for ShellInjectionRule {
    fn id(&self) -> &str {
        "python/shell-injection"
    }

    fn description(&self) -> &str {
        "Scans for subprocess patterns with shell=True that may be vulnerable"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_calls(&mut cursor, |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Static pattern matching on AST text - not execution
                let has_shell_true = text.contains("subprocess") && text.contains("shell=True");
                let has_risky_module_call = text.contains("popen(");

                if has_shell_true || has_risky_module_call {
                    findings.push(create_finding(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Critical,
                        "Shell command execution pattern detected - review for injection risk",
                        Language::Python,
                    ));
                }
            }
        });
        findings
    }
}

/// DETECTS hardcoded secrets and credentials via pattern matching
pub struct HardcodedSecretRule;

impl Rule for HardcodedSecretRule {
    fn id(&self) -> &str {
        "python/hardcoded-secret"
    }

    fn description(&self) -> &str {
        "Scans variable names for potential hardcoded secrets"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        // Skip test/fixture files - they commonly contain fake secrets
        if is_test_or_fixture_file(&parsed.path) {
            return Vec::new();
        }

        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        let secret_keywords = [
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "auth_token",
            "private_key",
        ];

        find_assignments(&mut cursor, |node: Node| {
            if let Some(left) = node.child_by_field_name("left")
                && let Ok(var_name) = left.utf8_text(parsed.content.as_bytes())
            {
                let var_lower = var_name.to_lowercase();
                for keyword in &secret_keywords {
                    if var_lower.contains(keyword)
                        && let Some(right) = node.child_by_field_name("right")
                        && right.kind() == "string"
                    {
                        findings.push(create_finding(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Critical,
                            "Hardcoded credential pattern detected - use env vars",
                            Language::Python,
                        ));
                        break;
                    }
                }
            }
        });
        findings
    }
}

fn find_calls<F>(cursor: &mut tree_sitter::TreeCursor, mut callback: F)
where
    F: FnMut(Node),
{
    loop {
        let node = cursor.node();
        if node.kind() == "call" {
            callback(node);
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

fn find_assignments<F>(cursor: &mut tree_sitter::TreeCursor, mut callback: F)
where
    F: FnMut(Node),
{
    loop {
        let node = cursor.node();
        if node.kind() == "assignment" || node.kind() == "expression_statement" {
            callback(node);
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

// =============================================================================
// PICKLE DESERIALIZATION RULE
// =============================================================================

/// DETECTS dangerous pickle/cPickle deserialization patterns
///
/// Pickle deserialization can run arbitrary code when loading untrusted data.
/// This rule detects:
/// - `pickle.load()`, `pickle.loads()`
/// - `cPickle.load()`, `cPickle.loads()`
/// - `pandas.read_pickle()`
pub struct PickleDeserializationRule;

impl Rule for PickleDeserializationRule {
    fn id(&self) -> &str {
        "python/pickle-deserialization"
    }

    fn description(&self) -> &str {
        "Detects dangerous pickle deserialization that can run arbitrary code"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Dangerous pickle functions
        let dangerous_patterns = [
            ("pickle", "load"),
            ("pickle", "loads"),
            ("cPickle", "load"),
            ("cPickle", "loads"),
            ("_pickle", "load"),
            ("_pickle", "loads"),
        ];

        find_calls(&mut cursor, |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Check for module.function pattern
                for (module, func) in &dangerous_patterns {
                    let pattern = format!("{}.{}", module, func);
                    if text.contains(&pattern) {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Error,
                            &format!(
                                "Pickle deserialization detected ({}) - can run arbitrary code. Use safer alternatives like JSON.",
                                pattern
                            ),
                            Language::Python,
                            Confidence::High,
                        ));
                        return;
                    }
                }

                // Check for pandas.read_pickle
                if text.contains("read_pickle") {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Error,
                        "pandas.read_pickle() can run arbitrary code - ensure data source is trusted or use safer formats like CSV/Parquet",
                        Language::Python,
                        Confidence::High,
                    ));
                }
            }
        });
        findings
    }
}

// =============================================================================
// SSTI (SERVER-SIDE TEMPLATE INJECTION) RULE
// =============================================================================

/// DETECTS Server-Side Template Injection (SSTI) vulnerabilities
///
/// SSTI occurs when user input is embedded in template strings without proper sanitization.
/// This rule detects:
/// - `render_template_string()` with f-strings or variables
/// - `Template().render()` with user input
/// - Jinja2 `Environment().from_string()`
pub struct SstiRule;

impl Rule for SstiRule {
    fn id(&self) -> &str {
        "python/ssti"
    }

    fn description(&self) -> &str {
        "Detects Server-Side Template Injection (SSTI) vulnerabilities"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_calls(&mut cursor, |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Check for render_template_string with dynamic content
                if text.contains("render_template_string") {
                    // Check if the argument is an f-string, concatenation, or variable
                    let is_dynamic = text.contains("f\"")
                        || text.contains("f'")
                        || text.contains(" + ")
                        || text.contains(".format(")
                        || text.contains("%");

                    // Also flag if argument is a variable (not a string literal)
                    let has_string_literal = text.contains("render_template_string(\"")
                        || text.contains("render_template_string('")
                        || text.contains("render_template_string('''")
                        || text.contains("render_template_string(\"\"\"");

                    if is_dynamic || !has_string_literal {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Error,
                            "SSTI vulnerability: render_template_string() with dynamic content. Use render_template() with separate template files.",
                            Language::Python,
                            Confidence::High,
                        ));
                        return;
                    }
                }

                // Check for Jinja2 Environment().from_string()
                if text.contains("from_string(")
                    && (text.contains("Environment") || text.contains("env."))
                {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Error,
                        "SSTI vulnerability: Jinja2 from_string() with dynamic template. Ensure template content is not user-controlled.",
                        Language::Python,
                        Confidence::High,
                    ));
                    return;
                }

                // Check for Template().render() or Template(var).render()
                if text.contains("Template(") && text.contains(".render(") {
                    // Check if Template is constructed with a variable (not a string literal)
                    let has_literal_template = text.contains("Template(\"")
                        || text.contains("Template('")
                        || text.contains("Template('''")
                        || text.contains("Template(\"\"\"");

                    if !has_literal_template {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Error,
                            "SSTI vulnerability: Template() constructed with variable. Ensure template content is not user-controlled.",
                            Language::Python,
                            Confidence::High,
                        ));
                    }
                }
            }
        });
        findings
    }
}

// =============================================================================
// UNSAFE YAML RULE
// =============================================================================

/// DETECTS unsafe YAML loading patterns
///
/// `yaml.load()` without a safe Loader can run arbitrary Python code.
/// This rule detects:
/// - `yaml.load()` without `Loader=SafeLoader` or `Loader=yaml.SafeLoader`
/// - `yaml.unsafe_load()`
/// - `yaml.full_load()` (allows some Python objects)
pub struct UnsafeYamlRule;

impl Rule for UnsafeYamlRule {
    fn id(&self) -> &str {
        "python/unsafe-yaml"
    }

    fn description(&self) -> &str {
        "Detects unsafe YAML loading that can run arbitrary code"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_calls(&mut cursor, |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                // Check for yaml.unsafe_load() - always dangerous
                if text.contains("yaml.unsafe_load") || text.contains("yaml.full_load") {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Error,
                        "Unsafe YAML loading detected - can run arbitrary code. Use yaml.safe_load() instead.",
                        Language::Python,
                        Confidence::High,
                    ));
                    return;
                }

                // Check for yaml.load() without SafeLoader
                if text.contains("yaml.load(") {
                    // Check if SafeLoader is specified
                    let has_safe_loader = text.contains("SafeLoader")
                        || text.contains("safe_load")
                        || text.contains("CSafeLoader")
                        || text.contains("BaseLoader")
                        || text.contains("FullLoader"); // FullLoader is safer than UnsafeLoader

                    if !has_safe_loader {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Error,
                            "yaml.load() without SafeLoader can run arbitrary code. Use yaml.safe_load() or specify Loader=yaml.SafeLoader.",
                            Language::Python,
                            Confidence::High,
                        ));
                    }
                }
            }
        });
        findings
    }
}

// =============================================================================
// DJANGO RAW SQL RULE
// =============================================================================

/// DETECTS Django raw SQL patterns that may be vulnerable to SQL injection
///
/// Django provides safe query methods, but raw SQL can introduce injection vulnerabilities.
/// This rule detects:
/// - `RawSQL()` with string formatting
/// - `.extra()` with string formatting
/// - `.raw()` with string formatting
/// - `cursor.run_query()` with f-strings or % formatting
pub struct DjangoRawSqlRule;

impl Rule for DjangoRawSqlRule {
    fn id(&self) -> &str {
        "python/django-raw-sql"
    }

    fn description(&self) -> &str {
        "Detects Django raw SQL patterns that may be vulnerable to SQL injection"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        find_calls(&mut cursor, |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                let has_string_formatting = text.contains("f\"")
                    || text.contains("f'")
                    || text.contains(".format(")
                    || text.contains(" % ")
                    || text.contains("%(")
                    || text.contains(" + ");

                // Check for RawSQL with string formatting
                if text.contains("RawSQL(") && has_string_formatting {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "SQL injection risk: RawSQL() with string formatting. Use parameterized queries.",
                        Language::Python,
                        Confidence::Medium,
                    ));
                    return;
                }

                // Check for .extra() with string formatting
                if text.contains(".extra(") && has_string_formatting {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "SQL injection risk: .extra() with string formatting. Use Django ORM methods or parameterized queries.",
                        Language::Python,
                        Confidence::Medium,
                    ));
                    return;
                }

                // Check for .raw() with string formatting
                if text.contains(".raw(") && has_string_formatting {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "SQL injection risk: .raw() with string formatting. Pass parameters as second argument.",
                        Language::Python,
                        Confidence::Medium,
                    ));
                    return;
                }

                // Check for cursor methods with string formatting (run_query, run_sql, etc.)
                if (text.contains(".run_query(")
                    || text.contains(".run_sql(")
                    || text.contains(".executemany("))
                    && has_string_formatting
                {
                    findings.push(create_finding_with_confidence(
                        self.id(),
                        &node,
                        &parsed.path,
                        &parsed.content,
                        Severity::Warning,
                        "SQL injection risk: Database cursor method with string formatting. Use parameterized queries with placeholders.",
                        Language::Python,
                        Confidence::Medium,
                    ));
                }
            }
        });
        findings
    }
}

// =============================================================================
// PATH TRAVERSAL RULE
// =============================================================================

/// DETECTS path traversal vulnerabilities
///
/// Path traversal occurs when user input is used to construct file paths without validation.
/// This rule detects:
/// - `os.path.join()` with user input as second argument
/// - `open()` with string concatenation
/// - `pathlib.Path()` with untrusted input patterns
pub struct PathTraversalRule;

impl Rule for PathTraversalRule {
    fn id(&self) -> &str {
        "python/path-traversal"
    }

    fn description(&self) -> &str {
        "Detects potential path traversal vulnerabilities"
    }

    fn applies_to(&self, lang: Language) -> bool {
        lang == Language::Python
    }

    fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut cursor = parsed.tree.walk();

        // Common user input indicators
        let user_input_indicators = [
            "request.",
            "params",
            "query",
            "form",
            "args",
            "input",
            "user",
            "filename",
            "file_name",
            "filepath",
            "file_path",
        ];

        find_calls(&mut cursor, |node: Node| {
            if let Ok(text) = node.utf8_text(parsed.content.as_bytes()) {
                let text_lower = text.to_lowercase();

                // Check for os.path.join with dynamic path
                if text.contains("os.path.join(") || text.contains("path.join(") {
                    // Check if any user input indicator is present
                    let has_user_input = user_input_indicators
                        .iter()
                        .any(|indicator| text_lower.contains(indicator));

                    // Also flag if there's string concatenation or f-strings
                    let has_dynamic_content = text.contains(" + ")
                        || text.contains("f\"")
                        || text.contains("f'")
                        || text.contains(".format(");

                    if has_user_input || has_dynamic_content {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "Path traversal risk: os.path.join() with user input. Validate path doesn't escape base directory using os.path.realpath().",
                            Language::Python,
                            Confidence::Medium,
                        ));
                        return;
                    }
                }

                // Check for open() with string concatenation
                if text.starts_with("open(") || text.contains(" open(") {
                    let has_concat =
                        text.contains(" + ") || text.contains("f\"") || text.contains("f'");
                    let has_user_input = user_input_indicators
                        .iter()
                        .any(|indicator| text_lower.contains(indicator));

                    if has_concat || has_user_input {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "Path traversal risk: open() with dynamic path. Validate and sanitize file path before use.",
                            Language::Python,
                            Confidence::Medium,
                        ));
                        return;
                    }
                }

                // Check for pathlib.Path() with user input
                if text.contains("Path(") {
                    let has_user_input = user_input_indicators
                        .iter()
                        .any(|indicator| text_lower.contains(indicator));

                    let has_dynamic_content = text.contains(" + ")
                        || text.contains("f\"")
                        || text.contains("f'")
                        || text.contains(".format(");

                    // Also check for Path() / operator which can be vulnerable
                    let has_division = text.contains(" / ");

                    if has_user_input || (has_dynamic_content && !has_division) {
                        findings.push(create_finding_with_confidence(
                            self.id(),
                            &node,
                            &parsed.path,
                            &parsed.content,
                            Severity::Warning,
                            "Path traversal risk: pathlib.Path() with dynamic input. Use resolve() and check if result is within expected directory.",
                            Language::Python,
                            Confidence::Medium,
                        ));
                    }
                }
            }
        });
        findings
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;
    use rma_common::RmaConfig;
    use rma_parser::ParserEngine;
    use std::path::Path;

    fn parse_python(content: &str) -> ParsedFile {
        let config = RmaConfig::default();
        let parser = ParserEngine::new(config);
        parser.parse_file(Path::new("test.py"), content).unwrap()
    }

    // =========================================================================
    // Pickle Deserialization Tests
    // =========================================================================

    #[test]
    fn test_pickle_load_flagged() {
        let content = r#"
import pickle
data = pickle.load(file)
"#;
        let parsed = parse_python(content);
        let rule = PickleDeserializationRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "pickle.load() should be flagged");
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("pickle.load"));
    }

    #[test]
    fn test_pickle_loads_flagged() {
        let content = r#"
import pickle
data = pickle.loads(raw_data)
"#;
        let parsed = parse_python(content);
        let rule = PickleDeserializationRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "pickle.loads() should be flagged");
    }

    #[test]
    fn test_cpickle_flagged() {
        let content = r#"
import cPickle
data = cPickle.load(file)
"#;
        let parsed = parse_python(content);
        let rule = PickleDeserializationRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "cPickle.load() should be flagged");
    }

    #[test]
    fn test_pandas_read_pickle_flagged() {
        let content = r#"
import pandas as pd
df = pd.read_pickle("data.pkl")
"#;
        let parsed = parse_python(content);
        let rule = PickleDeserializationRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "pandas.read_pickle() should be flagged");
    }

    #[test]
    fn test_pickle_dump_not_flagged() {
        let content = r#"
import pickle
pickle.dump(data, file)
"#;
        let parsed = parse_python(content);
        let rule = PickleDeserializationRule;
        let findings = rule.check(&parsed);
        assert!(findings.is_empty(), "pickle.dump() should not be flagged");
    }

    // =========================================================================
    // SSTI Tests
    // =========================================================================

    #[test]
    fn test_render_template_string_with_fstring_flagged() {
        let content = r#"
from flask import render_template_string
html = render_template_string(f"Hello {name}!")
"#;
        let parsed = parse_python(content);
        let rule = SstiRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "render_template_string with f-string should be flagged"
        );
        assert!(findings[0].message.contains("SSTI"));
    }

    #[test]
    fn test_render_template_string_with_variable_flagged() {
        let content = r#"
from flask import render_template_string
html = render_template_string(user_template)
"#;
        let parsed = parse_python(content);
        let rule = SstiRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "render_template_string with variable should be flagged"
        );
    }

    #[test]
    fn test_jinja2_from_string_flagged() {
        let content = r#"
from jinja2 import Environment
env = Environment()
template = env.from_string(user_input)
"#;
        let parsed = parse_python(content);
        let rule = SstiRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "Jinja2 from_string() should be flagged");
    }

    #[test]
    fn test_template_render_with_variable_flagged() {
        let content = r#"
from jinja2 import Template
result = Template(user_template).render(name="World")
"#;
        let parsed = parse_python(content);
        let rule = SstiRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "Template() with variable should be flagged"
        );
    }

    #[test]
    fn test_template_with_literal_not_flagged() {
        let content = r#"
from jinja2 import Template
result = Template("Hello {{ name }}!").render(name="World")
"#;
        let parsed = parse_python(content);
        let rule = SstiRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Template() with string literal should not be flagged"
        );
    }

    // =========================================================================
    // Unsafe YAML Tests
    // =========================================================================

    #[test]
    fn test_yaml_load_without_loader_flagged() {
        let content = r#"
import yaml
data = yaml.load(file_content)
"#;
        let parsed = parse_python(content);
        let rule = UnsafeYamlRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "yaml.load() without Loader should be flagged"
        );
        assert!(findings[0].message.contains("SafeLoader"));
    }

    #[test]
    fn test_yaml_unsafe_load_flagged() {
        let content = r#"
import yaml
data = yaml.unsafe_load(content)
"#;
        let parsed = parse_python(content);
        let rule = UnsafeYamlRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "yaml.unsafe_load() should be flagged");
    }

    #[test]
    fn test_yaml_full_load_flagged() {
        let content = r#"
import yaml
data = yaml.full_load(content)
"#;
        let parsed = parse_python(content);
        let rule = UnsafeYamlRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "yaml.full_load() should be flagged");
    }

    #[test]
    fn test_yaml_load_with_safe_loader_not_flagged() {
        let content = r#"
import yaml
data = yaml.load(content, Loader=yaml.SafeLoader)
"#;
        let parsed = parse_python(content);
        let rule = UnsafeYamlRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "yaml.load() with SafeLoader should not be flagged"
        );
    }

    #[test]
    fn test_yaml_safe_load_not_flagged() {
        let content = r#"
import yaml
data = yaml.safe_load(content)
"#;
        let parsed = parse_python(content);
        let rule = UnsafeYamlRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "yaml.safe_load() should not be flagged"
        );
    }

    // =========================================================================
    // Django Raw SQL Tests
    // =========================================================================

    #[test]
    fn test_rawsql_with_fstring_flagged() {
        let content = r#"
from django.db.models.expressions import RawSQL
val = RawSQL(f"SELECT * FROM users WHERE name = '{name}'")
"#;
        let parsed = parse_python(content);
        let rule = DjangoRawSqlRule;
        let findings = rule.check(&parsed);
        assert!(
            !findings.is_empty(),
            "RawSQL with f-string should be flagged"
        );
        let rawsql_finding = findings.iter().find(|f| f.message.contains("RawSQL"));
        assert!(
            rawsql_finding.is_some(),
            "Should have a finding about RawSQL"
        );
        assert_eq!(rawsql_finding.unwrap().severity, Severity::Warning);
    }

    #[test]
    fn test_extra_with_format_flagged() {
        let content = r#"
queryset.extra(where=["name = '%s'" % user_input])
"#;
        let parsed = parse_python(content);
        let rule = DjangoRawSqlRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            ".extra() with % formatting should be flagged"
        );
    }

    #[test]
    fn test_raw_with_concatenation_flagged() {
        let content = r#"
Model.objects.raw("SELECT * FROM table WHERE id = " + user_id)
"#;
        let parsed = parse_python(content);
        let rule = DjangoRawSqlRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            ".raw() with concatenation should be flagged"
        );
    }

    #[test]
    fn test_cursor_run_query_with_fstring_flagged() {
        let content = r#"
cursor.run_query(f"SELECT * FROM users WHERE id = {user_id}")
"#;
        let parsed = parse_python(content);
        let rule = DjangoRawSqlRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "cursor.run_query() with f-string should be flagged"
        );
    }

    #[test]
    fn test_cursor_with_params_not_flagged() {
        let content = r#"
cursor.run_query("SELECT * FROM users WHERE id = %s", [user_id])
"#;
        let parsed = parse_python(content);
        let rule = DjangoRawSqlRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "cursor with parameterized query should not be flagged"
        );
    }

    // =========================================================================
    // Path Traversal Tests
    // =========================================================================

    #[test]
    fn test_os_path_join_with_user_input_flagged() {
        let content = r#"
import os
path = os.path.join(base_dir, request.args.get('filename'))
"#;
        let parsed = parse_python(content);
        let rule = PathTraversalRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "os.path.join with user input should be flagged"
        );
        assert_eq!(findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_open_with_concatenation_flagged() {
        let content = r#"
f = open(base_path + user_filename, 'r')
"#;
        let parsed = parse_python(content);
        let rule = PathTraversalRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "open() with concatenation should be flagged"
        );
    }

    #[test]
    fn test_open_with_fstring_flagged() {
        let content = r#"
f = open(f"/uploads/{filename}", 'r')
"#;
        let parsed = parse_python(content);
        let rule = PathTraversalRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "open() with f-string should be flagged");
    }

    #[test]
    fn test_pathlib_with_user_input_flagged() {
        let content = r#"
from pathlib import Path
filepath = Path(request.form['filepath'])
"#;
        let parsed = parse_python(content);
        let rule = PathTraversalRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "Path() with user input should be flagged"
        );
    }

    #[test]
    fn test_os_path_join_with_static_path_not_flagged() {
        let content = r#"
import os
path = os.path.join(base_dir, "static", "file.txt")
"#;
        let parsed = parse_python(content);
        let rule = PathTraversalRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "os.path.join with static path should not be flagged"
        );
    }

    #[test]
    fn test_open_with_literal_not_flagged() {
        let content = r#"
f = open("config.txt", 'r')
"#;
        let parsed = parse_python(content);
        let rule = PathTraversalRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "open() with literal path should not be flagged"
        );
    }

    // =========================================================================
    // Existing Rule Tests (ensure they still pass)
    // =========================================================================

    #[test]
    fn test_dynamic_execution_rule() {
        let content = r#"
exec("print('hello')")
"#;
        let parsed = parse_python(content);
        let rule = DynamicExecutionRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "exec() should be flagged");
    }

    #[test]
    fn test_shell_injection_rule() {
        let content = r#"
import subprocess
subprocess.call(cmd, shell=True)
"#;
        let parsed = parse_python(content);
        let rule = ShellInjectionRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "subprocess with shell=True should be flagged"
        );
    }

    // =========================================================================
    // Additional Pickle Deserialization Tests (Phase 5 coverage)
    // =========================================================================

    #[test]
    fn test_pickle_internal_module_flagged() {
        let content = r#"
import _pickle
data = _pickle.load(file)
"#;
        let parsed = parse_python(content);
        let rule = PickleDeserializationRule;
        let findings = rule.check(&parsed);
        assert_eq!(findings.len(), 1, "_pickle.load() should be flagged");
    }

    #[test]
    fn test_pickle_dumps_not_flagged() {
        let content = r#"
import pickle
serialized = pickle.dumps(data)
"#;
        let parsed = parse_python(content);
        let rule = PickleDeserializationRule;
        let findings = rule.check(&parsed);
        assert!(findings.is_empty(), "pickle.dumps() should not be flagged");
    }

    #[test]
    fn test_json_load_not_flagged() {
        // Safe alternative to pickle should not be flagged
        let content = r#"
import json
data = json.load(file)
"#;
        let parsed = parse_python(content);
        let rule = PickleDeserializationRule;
        let findings = rule.check(&parsed);
        assert!(findings.is_empty(), "json.load() should not be flagged");
    }

    #[test]
    fn test_joblib_load_not_flagged() {
        // joblib.load uses pickle internally but is commonly used - not our focus here
        let content = r#"
import joblib
model = joblib.load("model.pkl")
"#;
        let parsed = parse_python(content);
        let rule = PickleDeserializationRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "joblib.load() is not flagged by pickle rule"
        );
    }

    // =========================================================================
    // Additional SSTI Tests (Phase 5 coverage)
    // =========================================================================

    #[test]
    fn test_ssti_render_template_file_not_flagged() {
        let content = r#"
from flask import render_template
html = render_template("index.html", name=name)
"#;
        let parsed = parse_python(content);
        let rule = SstiRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "render_template() with file should not be flagged"
        );
    }

    #[test]
    fn test_ssti_jinja2_file_loader_not_flagged() {
        let content = r#"
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader("templates"))
template = env.get_template("page.html")
result = template.render(data=data)
"#;
        let parsed = parse_python(content);
        let rule = SstiRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Jinja2 with FileSystemLoader should not be flagged"
        );
    }

    #[test]
    fn test_ssti_format_string_in_template_flagged() {
        let content = r#"
from flask import render_template_string
html = render_template_string("Hello {}".format(name))
"#;
        let parsed = parse_python(content);
        let rule = SstiRule;
        let findings = rule.check(&parsed);
        assert_eq!(
            findings.len(),
            1,
            "render_template_string with .format() should be flagged"
        );
    }

    // =========================================================================
    // Additional Unsafe YAML Tests (Phase 5 coverage)
    // =========================================================================

    #[test]
    fn test_yaml_load_with_csafeloader_not_flagged() {
        let content = r#"
import yaml
data = yaml.load(content, Loader=yaml.CSafeLoader)
"#;
        let parsed = parse_python(content);
        let rule = UnsafeYamlRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "yaml.load() with CSafeLoader should not be flagged"
        );
    }

    #[test]
    fn test_safe_yaml_patterns_reviewed() {
        // Test that we don't have false positives on obviously safe patterns
        let content = r#"
import yaml
# Safe: yaml.safe_load is the recommended way
data1 = yaml.safe_load(content)
# Safe: BaseLoader for simple types only
data2 = yaml.load(content, Loader=yaml.BaseLoader)
"#;
        let parsed = parse_python(content);
        let rule = UnsafeYamlRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Safe yaml patterns should not be flagged"
        );
    }

    // =========================================================================
    // Additional Django Raw SQL Tests (Phase 5 coverage)
    // =========================================================================

    #[test]
    fn test_django_raw_with_params_not_flagged() {
        let content = r#"
users = User.objects.raw("SELECT * FROM users WHERE id = %s", [user_id])
"#;
        let parsed = parse_python(content);
        let rule = DjangoRawSqlRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            ".raw() with parameterized query should not be flagged"
        );
    }

    #[test]
    fn test_django_orm_filter_not_flagged() {
        let content = r#"
users = User.objects.filter(name=user_input)
"#;
        let parsed = parse_python(content);
        let rule = DjangoRawSqlRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Django ORM filter should not be flagged"
        );
    }

    #[test]
    fn test_cursor_execute_with_params_not_flagged() {
        let content = r#"
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"#;
        let parsed = parse_python(content);
        let rule = DjangoRawSqlRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "cursor.execute with params should not be flagged"
        );
    }

    // =========================================================================
    // Additional Path Traversal Tests (Phase 5 coverage)
    // =========================================================================

    #[test]
    fn test_path_traversal_with_request_data_flagged() {
        // User input from request should always be flagged
        let content = r#"
import os
from flask import request
path = os.path.join(base_dir, request.form['filename'])
"#;
        let parsed = parse_python(content);
        let rule = PathTraversalRule;
        let findings = rule.check(&parsed);
        assert!(
            !findings.is_empty(),
            "Path with request data should be flagged"
        );
    }

    #[test]
    fn test_path_with_constant_subdir_not_flagged() {
        let content = r#"
import os
path = os.path.join(base_dir, "static", "images", "logo.png")
"#;
        let parsed = parse_python(content);
        let rule = PathTraversalRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Path with constant subdirectories should not be flagged"
        );
    }

    #[test]
    fn test_pathlib_with_static_parts_not_flagged() {
        let content = r#"
from pathlib import Path
config_path = Path(__file__).parent / "config" / "settings.yaml"
"#;
        let parsed = parse_python(content);
        let rule = PathTraversalRule;
        let findings = rule.check(&parsed);
        assert!(
            findings.is_empty(),
            "Path with __file__ and static parts should not be flagged"
        );
    }
}
