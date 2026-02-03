//! Build script that translates Semgrep YAML rules into pre-compiled matchers.
//!
//! The translator converts each Semgrep pattern into the best matching strategy:
//! - Simple patterns → Tree-sitter queries (fast path, ~70% of rules)
//! - Regex patterns → Pre-validated regex (validated at build time)
//! - Complex patterns → AST walker config
//!
//! At runtime, no YAML parsing or pattern compilation happens - just executing
//! pre-compiled queries.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

// =============================================================================
// COMPILED RULE FORMAT (serialized into binary)
// =============================================================================

/// Matching strategy determined at build time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchStrategy {
    /// Fast path: tree-sitter query (pre-compiled S-expression)
    TreeSitterQuery {
        query: String,
        captures: Vec<String>,
    },
    /// Literal string search (fastest for simple cases)
    LiteralSearch {
        literals: Vec<String>,
        case_sensitive: bool,
    },
    /// Pre-validated regex pattern
    Regex { pattern: String },
    /// AST walker for complex patterns (pattern-inside, metavariable-regex)
    AstWalker {
        pattern: String,
        metavariables: Vec<String>,
    },
    /// Taint tracking mode
    Taint {
        sources: Vec<String>,
        sinks: Vec<String>,
        sanitizers: Vec<String>,
    },
    /// Rule was skipped (unsupported pattern)
    Skipped { reason: String },
}

/// Compiled rule with pre-determined matching strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompiledRule {
    id: String,
    message: String,
    severity: String,
    languages: Vec<String>,
    category: Option<String>,
    confidence: Option<String>,

    /// Pre-compiled matching strategy
    strategy: MatchStrategy,

    /// Additional negative patterns (pattern-not)
    pattern_not: Option<String>,

    /// Metadata
    cwe: Option<Vec<String>>,
    owasp: Option<Vec<String>>,
    references: Option<Vec<String>>,
    fix: Option<String>,

    /// Optimization: literal strings for fast pre-filtering
    literal_triggers: Vec<String>,
}

// =============================================================================
// RAW SEMGREP FORMAT (parsed from YAML)
// =============================================================================

#[derive(Debug, Deserialize)]
struct RuleFile {
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    id: String,
    message: String,
    severity: String,
    languages: Vec<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default, rename = "pattern-either")]
    pattern_either: Option<Vec<PatternClause>>,
    #[serde(default)]
    patterns: Option<Vec<PatternClause>>,
    #[serde(default, rename = "pattern-not")]
    pattern_not: Option<String>,
    #[serde(default, rename = "pattern-regex")]
    pattern_regex: Option<String>,
    #[serde(default, rename = "pattern-sources")]
    pattern_sources: Option<Vec<PatternClause>>,
    #[serde(default, rename = "pattern-sinks")]
    pattern_sinks: Option<Vec<PatternClause>>,
    #[serde(default, rename = "pattern-sanitizers")]
    pattern_sanitizers: Option<Vec<PatternClause>>,
    #[serde(default)]
    metadata: Option<RawMetadata>,
    #[serde(default)]
    fix: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PatternClause {
    Simple(String),
    Complex(HashMap<String, serde_yaml::Value>),
}

#[derive(Debug, Deserialize, Default)]
struct RawMetadata {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    confidence: Option<String>,
    #[serde(default)]
    cwe: Option<CweField>,
    #[serde(default)]
    owasp: Option<Vec<String>>,
    #[serde(default)]
    references: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CweField {
    Single(String),
    Multiple(Vec<String>),
}

/// Compiled rules organized by language
#[derive(Debug, Serialize, Deserialize, Default)]
struct CompiledRuleSet {
    by_language: HashMap<String, Vec<CompiledRule>>,
    generic: Vec<CompiledRule>,
    total_count: usize,
    skipped_count: usize,
}

// =============================================================================
// MAIN BUILD LOGIC
// =============================================================================

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let rules_dir = Path::new("rules");

    if !rules_dir.exists() {
        let empty = CompiledRuleSet::default();
        let compiled = bincode::serialize(&empty).unwrap();
        fs::write(Path::new(&out_dir).join("compiled_rules.bin"), &compiled).unwrap();
        println!("cargo:warning=No rules directory found, embedding empty ruleset");
        return;
    }

    let mut rule_set = CompiledRuleSet::default();
    let mut errors = 0;
    let mut success = 0;
    let mut skipped = 0;

    for entry in WalkDir::new(rules_dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path.extension().and_then(|e| e.to_str());
        if !matches!(ext, Some("yaml") | Some("yml")) {
            continue;
        }

        match process_rule_file(path) {
            Ok(rules) => {
                for rule in rules {
                    let is_skipped = matches!(rule.strategy, MatchStrategy::Skipped { .. });

                    let primary_lang = rule
                        .languages
                        .first()
                        .map(|s| s.to_lowercase())
                        .unwrap_or_else(|| "generic".to_string());

                    if primary_lang == "generic" || rule.languages.is_empty() {
                        rule_set.generic.push(rule);
                    } else {
                        rule_set
                            .by_language
                            .entry(primary_lang)
                            .or_default()
                            .push(rule);
                    }

                    if is_skipped {
                        skipped += 1;
                    } else {
                        success += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("cargo:warning=Failed to process {}: {}", path.display(), e);
                errors += 1;
            }
        }
    }

    rule_set.total_count = success;
    rule_set.skipped_count = skipped;

    let compiled = bincode::serialize(&rule_set).unwrap();
    let dest = Path::new(&out_dir).join("compiled_rules.bin");
    fs::write(&dest, &compiled).unwrap();

    println!("cargo:rerun-if-changed=rules/");
    println!(
        "cargo:warning=Compiled {} rules ({} skipped, {} errors) into {} bytes",
        success,
        skipped,
        errors,
        compiled.len()
    );
}

fn process_rule_file(path: &Path) -> Result<Vec<CompiledRule>, String> {
    let content = fs::read_to_string(path).map_err(|e| format!("read error: {}", e))?;

    let file: RuleFile =
        serde_yaml::from_str(&content).map_err(|e| format!("parse error: {}", e))?;

    let mut compiled = Vec::new();
    for rule in file.rules {
        compiled.push(compile_rule(rule));
    }

    Ok(compiled)
}

// =============================================================================
// PATTERN TRANSLATION
// =============================================================================

fn compile_rule(raw: RawRule) -> CompiledRule {
    // Determine the matching strategy first (before consuming raw fields)
    let strategy = determine_strategy(&raw);

    // Extract literal triggers before consuming fields
    let literal_triggers = extract_literals_from_rule(&raw);

    let metadata = raw.metadata.unwrap_or_default();

    // Extract CWE
    let cwe = metadata.cwe.map(|c| match c {
        CweField::Single(s) => vec![s],
        CweField::Multiple(v) => v,
    });

    CompiledRule {
        id: raw.id,
        message: raw.message,
        severity: raw.severity.to_uppercase(),
        languages: raw
            .languages
            .into_iter()
            .map(|l| l.to_lowercase())
            .collect(),
        category: metadata.category,
        confidence: metadata.confidence,
        strategy,
        pattern_not: raw.pattern_not,
        cwe,
        owasp: metadata.owasp,
        references: metadata.references,
        fix: raw.fix,
        literal_triggers,
    }
}

/// Determine the best matching strategy for a rule
fn determine_strategy(raw: &RawRule) -> MatchStrategy {
    // Check for taint mode first
    if raw.mode.as_deref() == Some("taint")
        || raw.pattern_sources.is_some()
        || raw.pattern_sinks.is_some()
    {
        return compile_taint_strategy(raw);
    }

    // Check for regex pattern
    if let Some(ref regex) = raw.pattern_regex {
        return compile_regex_strategy(regex);
    }

    // Check for simple pattern
    if let Some(ref pattern) = raw.pattern {
        return translate_pattern(pattern, &raw.languages);
    }

    // Check for pattern-either
    if let Some(ref patterns) = raw.pattern_either {
        return compile_pattern_either(patterns, &raw.languages);
    }

    // Check for patterns array (complex)
    if let Some(ref patterns) = raw.patterns {
        return compile_complex_patterns(patterns, &raw.languages);
    }

    MatchStrategy::Skipped {
        reason: "No pattern found".to_string(),
    }
}

/// Compile taint mode strategy
fn compile_taint_strategy(raw: &RawRule) -> MatchStrategy {
    let sources: Vec<String> = raw
        .pattern_sources
        .as_ref()
        .map(|clauses| clauses.iter().filter_map(extract_pattern_string).collect())
        .unwrap_or_default();

    let sinks: Vec<String> = raw
        .pattern_sinks
        .as_ref()
        .map(|clauses| clauses.iter().filter_map(extract_pattern_string).collect())
        .unwrap_or_default();

    let sanitizers: Vec<String> = raw
        .pattern_sanitizers
        .as_ref()
        .map(|clauses| clauses.iter().filter_map(extract_pattern_string).collect())
        .unwrap_or_default();

    if sources.is_empty() && sinks.is_empty() {
        return MatchStrategy::Skipped {
            reason: "Taint rule with no sources or sinks".to_string(),
        };
    }

    MatchStrategy::Taint {
        sources,
        sinks,
        sanitizers,
    }
}

/// Compile regex pattern - validate at build time
fn compile_regex_strategy(pattern: &str) -> MatchStrategy {
    // Check for unsupported regex features
    if pattern.contains("(?!")
        || pattern.contains("(?=")
        || pattern.contains("(?<")
        || pattern.contains("(?<=")
    {
        return MatchStrategy::Skipped {
            reason: "Look-ahead/look-behind not supported".to_string(),
        };
    }

    // Validate the regex compiles
    match regex::Regex::new(pattern) {
        Ok(_) => MatchStrategy::Regex {
            pattern: pattern.to_string(),
        },
        Err(e) => MatchStrategy::Skipped {
            reason: format!("Invalid regex: {}", e),
        },
    }
}

/// Translate a Semgrep pattern to the best matching strategy
fn translate_pattern(pattern: &str, languages: &[String]) -> MatchStrategy {
    // Check if it's a simple literal (no metavariables)
    if !pattern.contains('$') && !pattern.contains("...") {
        let literals = extract_literals_from_pattern(pattern);
        if !literals.is_empty() {
            return MatchStrategy::LiteralSearch {
                literals,
                case_sensitive: true,
            };
        }
    }

    // Try to translate to tree-sitter query
    if let Some(query) = pattern_to_tree_sitter_query(pattern, languages) {
        let captures = extract_metavariables(pattern);
        return MatchStrategy::TreeSitterQuery { query, captures };
    }

    // Fall back to AST walker
    let metavariables = extract_metavariables(pattern);
    MatchStrategy::AstWalker {
        pattern: pattern.to_string(),
        metavariables,
    }
}

/// Compile pattern-either (any of these patterns)
fn compile_pattern_either(patterns: &[PatternClause], _languages: &[String]) -> MatchStrategy {
    let mut all_literals = Vec::new();

    for clause in patterns {
        if let Some(pattern) = extract_pattern_string(clause) {
            // If any pattern has metavariables, fall back to AST walker
            if pattern.contains('$') || pattern.contains("...") {
                let metavars = extract_metavariables(&pattern);
                return MatchStrategy::AstWalker {
                    pattern,
                    metavariables: metavars,
                };
            }
            all_literals.extend(extract_literals_from_pattern(&pattern));
        }
    }

    if !all_literals.is_empty() {
        MatchStrategy::LiteralSearch {
            literals: all_literals,
            case_sensitive: true,
        }
    } else {
        MatchStrategy::Skipped {
            reason: "Could not extract patterns from pattern-either".to_string(),
        }
    }
}

/// Compile complex patterns array
fn compile_complex_patterns(patterns: &[PatternClause], languages: &[String]) -> MatchStrategy {
    // Complex patterns with pattern-inside, metavariable-regex need AST walker
    for clause in patterns {
        if let PatternClause::Complex(map) = clause {
            // Check for complex features that need AST walker
            if map.contains_key("pattern-inside")
                || map.contains_key("pattern-not-inside")
                || map.contains_key("metavariable-regex")
                || map.contains_key("metavariable-pattern")
                || map.contains_key("focus-metavariable")
            {
                // Extract the main pattern if possible
                if let Some(pattern) = extract_pattern_string(clause) {
                    let metavars = extract_metavariables(&pattern);
                    return MatchStrategy::AstWalker {
                        pattern,
                        metavariables: metavars,
                    };
                }
            }
        }
    }

    // Try to find a simple pattern
    for clause in patterns {
        if let Some(pattern) = extract_pattern_string(clause) {
            return translate_pattern(&pattern, languages);
        }
    }

    MatchStrategy::Skipped {
        reason: "Could not extract usable pattern".to_string(),
    }
}

// =============================================================================
// TREE-SITTER QUERY GENERATION
// =============================================================================

/// Convert a Semgrep pattern to a tree-sitter query S-expression
fn pattern_to_tree_sitter_query(pattern: &str, languages: &[String]) -> Option<String> {
    let lang = languages.first().map(|s| s.as_str()).unwrap_or("generic");

    // Simple function call: func($ARG) or $OBJ.method($ARG)
    if let Some(query) = translate_call_pattern(pattern, lang) {
        return Some(query);
    }

    // Assignment: $X = $Y
    if let Some(query) = translate_assignment_pattern(pattern, lang) {
        return Some(query);
    }

    // String literal patterns
    if let Some(query) = translate_string_pattern(pattern, lang) {
        return Some(query);
    }

    None
}

/// Translate function call patterns like `func($X)` or `$OBJ.method($...)`
fn translate_call_pattern(pattern: &str, lang: &str) -> Option<String> {
    // Match: identifier($...) or $VAR.identifier($...)
    let call_re = regex::Regex::new(r"^(\$\w+\.)?(\w+)\s*\((.*)\)$").ok()?;

    let caps = call_re.captures(pattern.trim())?;
    let receiver = caps.get(1).map(|m| m.as_str().trim_end_matches('.'));
    let method = caps.get(2)?.as_str();
    let _args = caps.get(3).map(|m| m.as_str());

    // Generate tree-sitter query based on language
    let query = match lang {
        "python" => {
            if let Some(_recv) = receiver {
                format!(
                    r#"(call function: (attribute object: (_) @receiver attribute: (identifier) @method (#eq? @method "{}")) arguments: (argument_list) @args)"#,
                    method
                )
            } else {
                format!(
                    r#"(call function: (identifier) @func (#eq? @func "{}") arguments: (argument_list) @args)"#,
                    method
                )
            }
        }
        "javascript" | "typescript" => {
            if let Some(_recv) = receiver {
                format!(
                    r#"(call_expression function: (member_expression object: (_) @receiver property: (property_identifier) @method (#eq? @method "{}")) arguments: (arguments) @args)"#,
                    method
                )
            } else {
                format!(
                    r#"(call_expression function: (identifier) @func (#eq? @func "{}") arguments: (arguments) @args)"#,
                    method
                )
            }
        }
        "java" => {
            if let Some(_recv) = receiver {
                format!(
                    r#"(method_invocation object: (_) @receiver name: (identifier) @method (#eq? @method "{}") arguments: (argument_list) @args)"#,
                    method
                )
            } else {
                format!(
                    r#"(method_invocation name: (identifier) @method (#eq? @method "{}") arguments: (argument_list) @args)"#,
                    method
                )
            }
        }
        "go" => {
            if let Some(_recv) = receiver {
                format!(
                    r#"(call_expression function: (selector_expression operand: (_) @receiver field: (field_identifier) @method (#eq? @method "{}")) arguments: (argument_list) @args)"#,
                    method
                )
            } else {
                format!(
                    r#"(call_expression function: (identifier) @func (#eq? @func "{}") arguments: (argument_list) @args)"#,
                    method
                )
            }
        }
        "rust" => {
            if let Some(_recv) = receiver {
                format!(
                    r#"(call_expression function: (field_expression value: (_) @receiver field: (field_identifier) @method (#eq? @method "{}")) arguments: (arguments) @args)"#,
                    method
                )
            } else {
                format!(
                    r#"(call_expression function: (identifier) @func (#eq? @func "{}") arguments: (arguments) @args)"#,
                    method
                )
            }
        }
        _ => return None,
    };

    Some(query)
}

/// Translate assignment patterns like `$X = $Y`
fn translate_assignment_pattern(pattern: &str, lang: &str) -> Option<String> {
    if !pattern.contains(" = ") && !pattern.contains("=") {
        return None;
    }

    // Very simple assignment detection
    let assign_re = regex::Regex::new(r"^(\$?\w+)\s*=\s*(.+)$").ok()?;
    let caps = assign_re.captures(pattern.trim())?;

    let _lhs = caps.get(1)?.as_str();
    let _rhs = caps.get(2)?.as_str();

    // Generate generic assignment query
    let query = match lang {
        "python" => r#"(assignment left: (_) @lhs right: (_) @rhs)"#.to_string(),
        "javascript" | "typescript" => {
            r#"(assignment_expression left: (_) @lhs right: (_) @rhs)"#.to_string()
        }
        "java" => r#"(assignment_expression left: (_) @lhs right: (_) @rhs)"#.to_string(),
        _ => return None,
    };

    Some(query)
}

/// Translate string literal patterns
fn translate_string_pattern(pattern: &str, lang: &str) -> Option<String> {
    // Check if pattern is looking for a string containing specific text
    if pattern.starts_with('"') && pattern.ends_with('"') {
        let inner = &pattern[1..pattern.len() - 1];
        let query = match lang {
            "python" => format!(r#"(string) @str (#match? @str "{}")"#, inner),
            "javascript" | "typescript" => format!(r#"(string) @str (#match? @str "{}")"#, inner),
            "java" => format!(r#"(string_literal) @str (#match? @str "{}")"#, inner),
            _ => return None,
        };
        return Some(query);
    }
    None
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

fn extract_pattern_string(clause: &PatternClause) -> Option<String> {
    match clause {
        PatternClause::Simple(s) => Some(s.clone()),
        PatternClause::Complex(map) => map
            .get("pattern")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                map.get("pattern-inside")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            }),
    }
}

/// Extract metavariables from a pattern
fn extract_metavariables(pattern: &str) -> Vec<String> {
    let re = regex::Regex::new(r"\$(\.\.\.)?\w+").unwrap();
    re.find_iter(pattern)
        .map(|m| m.as_str().to_string())
        .collect()
}

fn extract_literals_from_rule(raw: &RawRule) -> Vec<String> {
    let mut literals = Vec::new();

    if let Some(ref p) = raw.pattern {
        literals.extend(extract_literals_from_pattern(p));
    }

    if let Some(ref patterns) = raw.pattern_either {
        for clause in patterns {
            if let Some(p) = extract_pattern_string(clause) {
                literals.extend(extract_literals_from_pattern(&p));
            }
        }
    }

    // Deduplicate and filter
    literals.sort();
    literals.dedup();
    literals.retain(|l| l.len() >= 3);
    if literals.len() > 5 {
        literals.truncate(5);
    }

    literals
}

fn extract_literals_from_pattern(pattern: &str) -> Vec<String> {
    let mut literals = Vec::new();

    for word in pattern.split(|c: char| c.is_whitespace() || "(){}[]<>=!|&,;:\"'`".contains(c)) {
        let word = word.trim();

        // Skip metavariables
        if word.starts_with('$') || word == "..." {
            continue;
        }

        // Skip very short words
        if word.len() < 3 {
            continue;
        }

        // Skip all-caps short words (likely type params)
        if word.chars().all(|c| c.is_uppercase() || c == '_') && word.len() <= 3 {
            continue;
        }

        literals.push(word.to_string());
    }

    literals
}
