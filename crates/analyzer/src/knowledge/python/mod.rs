//! Python framework knowledge profiles
//!
//! This module provides security-relevant knowledge about Python web frameworks
//! including Flask, Django, and FastAPI. Each profile defines:
//! - Taint sources (where user input enters)
//! - Security sinks (dangerous operations)
//! - Sanitizers (functions that neutralize tainted data)
//! - Safe patterns (inherently secure APIs)
//! - Dangerous patterns (code patterns that indicate potential issues)

mod django;
mod fastapi;
mod flask;

use crate::knowledge::types::FrameworkProfile;

/// Get all Python framework profiles
pub fn all_profiles() -> Vec<&'static FrameworkProfile> {
    vec![
        &flask::FLASK_PROFILE,
        &django::DJANGO_PROFILE,
        &fastapi::FASTAPI_PROFILE,
    ]
}

/// Python-specific dangerous patterns that apply regardless of framework
///
/// These are general Python security antipatterns that should be flagged
/// in any Python codebase.
pub mod common_patterns {
    use crate::knowledge::types::{DangerousPattern, PatternKind, SafePattern};
    use rma_common::Severity;

    /// Dangerous patterns common to all Python code
    pub static PYTHON_DANGEROUS_PATTERNS: &[DangerousPattern] = &[
        // Code execution vulnerabilities
        DangerousPattern {
            name: "eval_with_user_input",
            pattern: PatternKind::MethodCall("eval"),
            rule_id: "python/dangerous-eval",
            severity: Severity::Critical,
            description: "eval() runs arbitrary Python code. Never use with user input.",
            cwe: Some("CWE-95"),
        },
        DangerousPattern {
            name: "exec_with_user_input",
            pattern: PatternKind::MethodCall("exec"),
            rule_id: "python/dangerous-exec",
            severity: Severity::Critical,
            description: "exec() runs arbitrary Python code. Never use with user input.",
            cwe: Some("CWE-95"),
        },
        DangerousPattern {
            name: "compile_with_user_input",
            pattern: PatternKind::MethodCall("compile"),
            rule_id: "python/dangerous-compile",
            severity: Severity::Error,
            description: "compile() can be used to run arbitrary code when combined with eval/exec.",
            cwe: Some("CWE-95"),
        },
        // Deserialization vulnerabilities
        DangerousPattern {
            name: "pickle_loads",
            pattern: PatternKind::MethodCall("pickle.loads"),
            rule_id: "python/insecure-deserialization-pickle",
            severity: Severity::Critical,
            description: "pickle.loads() deserializes arbitrary Python objects. Can run code during unpickling.",
            cwe: Some("CWE-502"),
        },
        DangerousPattern {
            name: "pickle_load",
            pattern: PatternKind::MethodCall("pickle.load"),
            rule_id: "python/insecure-deserialization-pickle",
            severity: Severity::Critical,
            description: "pickle.load() deserializes arbitrary Python objects. Can run code during unpickling.",
            cwe: Some("CWE-502"),
        },
        DangerousPattern {
            name: "yaml_load_unsafe",
            pattern: PatternKind::Regex(r"yaml\.load\([^)]+(?<!Loader\s*=\s*yaml\.SafeLoader)\)"),
            rule_id: "python/insecure-yaml-load",
            severity: Severity::Critical,
            description: "yaml.load() without SafeLoader can run arbitrary code. Use yaml.safe_load() instead.",
            cwe: Some("CWE-502"),
        },
        DangerousPattern {
            name: "marshal_loads",
            pattern: PatternKind::MethodCall("marshal.loads"),
            rule_id: "python/insecure-deserialization-marshal",
            severity: Severity::Error,
            description: "marshal module is not secure against maliciously constructed data.",
            cwe: Some("CWE-502"),
        },
        DangerousPattern {
            name: "shelve_open",
            pattern: PatternKind::MethodCall("shelve.open"),
            rule_id: "python/insecure-shelve",
            severity: Severity::Error,
            description: "shelve uses pickle internally. Do not use with untrusted data sources.",
            cwe: Some("CWE-502"),
        },
        // Dynamic import vulnerabilities
        DangerousPattern {
            name: "dynamic_import",
            pattern: PatternKind::MethodCall("__import__"),
            rule_id: "python/dangerous-import",
            severity: Severity::Error,
            description: "__import__() with user input can load arbitrary modules.",
            cwe: Some("CWE-94"),
        },
        DangerousPattern {
            name: "importlib_import",
            pattern: PatternKind::MethodCall("importlib.import_module"),
            rule_id: "python/dangerous-import",
            severity: Severity::Error,
            description: "importlib.import_module() with user input can load arbitrary modules.",
            cwe: Some("CWE-94"),
        },
        // Command invocation vulnerabilities
        DangerousPattern {
            name: "os_system",
            pattern: PatternKind::MethodCall("os.system"),
            rule_id: "python/shell-invocation-os-system",
            severity: Severity::Critical,
            description: "os.system() invokes commands in a shell. Vulnerable to shell metacharacter attacks.",
            cwe: Some("CWE-78"),
        },
        DangerousPattern {
            name: "os_popen",
            pattern: PatternKind::MethodCall("os.popen"),
            rule_id: "python/shell-invocation-os-popen",
            severity: Severity::Critical,
            description: "os.popen() invokes commands in a shell. Vulnerable to shell metacharacter attacks.",
            cwe: Some("CWE-78"),
        },
        DangerousPattern {
            name: "subprocess_shell_true",
            pattern: PatternKind::Regex(r"subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True"),
            rule_id: "python/shell-invocation-subprocess-shell",
            severity: Severity::Critical,
            description: "subprocess with shell=True is vulnerable to shell attacks. Use shell=False with argument list.",
            cwe: Some("CWE-78"),
        },
        DangerousPattern {
            name: "commands_module",
            pattern: PatternKind::MethodCall("commands.getoutput"),
            rule_id: "python/shell-invocation-commands",
            severity: Severity::Critical,
            description: "commands module (Python 2) invokes commands in a shell. Vulnerable to shell attacks.",
            cwe: Some("CWE-78"),
        },
        // Path traversal vulnerabilities
        DangerousPattern {
            name: "open_with_user_path",
            pattern: PatternKind::Regex(r"open\([^)]*\+"),
            rule_id: "python/path-traversal-hint",
            severity: Severity::Warning,
            description: "File path concatenation may be vulnerable to path traversal. Use pathlib.Path.resolve() to validate.",
            cwe: Some("CWE-22"),
        },
        // SQL statement building (raw queries)
        DangerousPattern {
            name: "sql_string_format",
            pattern: PatternKind::Regex(r#"execute\([^)]*(%|\.format|f["'])"#),
            rule_id: "python/sql-string-building",
            severity: Severity::Critical,
            description: "SQL query built with string formatting is vulnerable to SQL attacks. Use parameterized queries.",
            cwe: Some("CWE-89"),
        },
        // SSRF vulnerabilities
        DangerousPattern {
            name: "requests_with_user_url",
            pattern: PatternKind::Regex(r"requests\.(get|post|put|delete|patch)\([^)]*\+"),
            rule_id: "python/ssrf-hint",
            severity: Severity::Warning,
            description: "URL built with user input may be vulnerable to SSRF. Validate URLs against allowlist.",
            cwe: Some("CWE-918"),
        },
        // Weak cryptography
        DangerousPattern {
            name: "md5_usage",
            pattern: PatternKind::MethodCall("hashlib.md5"),
            rule_id: "python/weak-crypto-md5",
            severity: Severity::Warning,
            description: "MD5 is cryptographically broken. Use SHA-256 or better for security purposes.",
            cwe: Some("CWE-328"),
        },
        DangerousPattern {
            name: "sha1_usage",
            pattern: PatternKind::MethodCall("hashlib.sha1"),
            rule_id: "python/weak-crypto-sha1",
            severity: Severity::Warning,
            description: "SHA-1 is cryptographically weak. Use SHA-256 or better for security purposes.",
            cwe: Some("CWE-328"),
        },
        DangerousPattern {
            name: "random_for_security",
            pattern: PatternKind::Regex(r"random\.(random|randint|choice|shuffle)"),
            rule_id: "python/insecure-random-hint",
            severity: Severity::Info,
            description: "random module is not cryptographically secure. Use secrets module for security-sensitive operations.",
            cwe: Some("CWE-330"),
        },
        // Hardcoded secrets
        DangerousPattern {
            name: "hardcoded_password",
            pattern: PatternKind::Regex(
                r#"(?i)(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["'][^"']+["']"#,
            ),
            rule_id: "python/hardcoded-secret",
            severity: Severity::Error,
            description: "Hardcoded credentials detected. Use environment variables or secret management.",
            cwe: Some("CWE-798"),
        },
        // Dangerous assert usage
        DangerousPattern {
            name: "assert_for_validation",
            pattern: PatternKind::Regex(r"assert\s+.*request"),
            rule_id: "python/assert-for-validation",
            severity: Severity::Error,
            description: "assert statements are removed in optimized mode (-O). Do not use for security validation.",
            cwe: Some("CWE-617"),
        },
        // Temporary file issues
        DangerousPattern {
            name: "tempfile_mktemp",
            pattern: PatternKind::MethodCall("tempfile.mktemp"),
            rule_id: "python/insecure-tempfile",
            severity: Severity::Warning,
            description: "tempfile.mktemp() is insecure due to race condition. Use tempfile.mkstemp() or NamedTemporaryFile().",
            cwe: Some("CWE-377"),
        },
        // XML vulnerabilities
        DangerousPattern {
            name: "xml_etree_parse",
            pattern: PatternKind::MethodCall("xml.etree.ElementTree.parse"),
            rule_id: "python/xxe-etree",
            severity: Severity::Warning,
            description: "xml.etree.ElementTree may be vulnerable to XXE attacks. Use defusedxml for untrusted input.",
            cwe: Some("CWE-611"),
        },
        DangerousPattern {
            name: "lxml_parse",
            pattern: PatternKind::Regex(
                r"lxml\.etree\.(parse|fromstring)\([^)]*(?<!resolve_entities\s*=\s*False)",
            ),
            rule_id: "python/xxe-lxml",
            severity: Severity::Warning,
            description: "lxml may be vulnerable to XXE attacks. Disable external entity resolution or use defusedxml.",
            cwe: Some("CWE-611"),
        },
    ];

    /// Safe patterns for Python
    pub static PYTHON_SAFE_PATTERNS: &[SafePattern] = &[
        SafePattern {
            name: "subprocess_list_args",
            pattern: "subprocess.run([...], shell=False)",
            reason: "Using argument list with shell=False prevents shell metacharacter attacks.",
        },
        SafePattern {
            name: "shlex_quote",
            pattern: "shlex.quote(user_input)",
            reason: "shlex.quote() properly escapes shell arguments.",
        },
        SafePattern {
            name: "ast_literal_eval",
            pattern: "ast.literal_eval()",
            reason: "ast.literal_eval() only evaluates literal expressions, safe for parsing data.",
        },
        SafePattern {
            name: "pathlib_resolve",
            pattern: "pathlib.Path(path).resolve()",
            reason: "pathlib.Path.resolve() resolves symlinks and normalizes paths, preventing traversal.",
        },
        SafePattern {
            name: "yaml_safe_load",
            pattern: "yaml.safe_load()",
            reason: "yaml.safe_load() only loads basic Python types, preventing code invocation.",
        },
        SafePattern {
            name: "parameterized_query",
            pattern: "cursor.execute(query, params)",
            reason: "Parameterized queries prevent SQL attacks by separating code from data.",
        },
        SafePattern {
            name: "secrets_module",
            pattern: "secrets.token_hex()",
            reason: "secrets module provides cryptographically secure random values.",
        },
        SafePattern {
            name: "defusedxml",
            pattern: "defusedxml.ElementTree.parse()",
            reason: "defusedxml prevents XXE and other XML attacks.",
        },
        SafePattern {
            name: "bcrypt_password",
            pattern: "bcrypt.hashpw()",
            reason: "bcrypt provides secure password hashing with salt and work factor.",
        },
        SafePattern {
            name: "argon2_password",
            pattern: "argon2.hash()",
            reason: "Argon2 is the recommended password hashing algorithm.",
        },
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_profiles_returns_expected_count() {
        let profiles = all_profiles();
        assert_eq!(profiles.len(), 3);
    }

    #[test]
    fn test_flask_profile_exists() {
        let profiles = all_profiles();
        assert!(profiles.iter().any(|p| p.name == "flask"));
    }

    #[test]
    fn test_django_profile_exists() {
        let profiles = all_profiles();
        assert!(profiles.iter().any(|p| p.name == "django"));
    }

    #[test]
    fn test_fastapi_profile_exists() {
        let profiles = all_profiles();
        assert!(profiles.iter().any(|p| p.name == "fastapi"));
    }

    #[test]
    fn test_common_dangerous_patterns() {
        assert!(!common_patterns::PYTHON_DANGEROUS_PATTERNS.is_empty());
        // Check that critical patterns exist
        assert!(
            common_patterns::PYTHON_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "eval_with_user_input")
        );
        assert!(
            common_patterns::PYTHON_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "pickle_loads")
        );
        assert!(
            common_patterns::PYTHON_DANGEROUS_PATTERNS
                .iter()
                .any(|p| p.name == "os_system")
        );
    }

    #[test]
    fn test_common_safe_patterns() {
        assert!(!common_patterns::PYTHON_SAFE_PATTERNS.is_empty());
        assert!(
            common_patterns::PYTHON_SAFE_PATTERNS
                .iter()
                .any(|p| p.name == "subprocess_list_args")
        );
        assert!(
            common_patterns::PYTHON_SAFE_PATTERNS
                .iter()
                .any(|p| p.name == "parameterized_query")
        );
    }
}
