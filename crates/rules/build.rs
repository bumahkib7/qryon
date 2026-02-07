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
        /// Original Semgrep pattern for regex fallback
        original_pattern: Option<String>,
    },
    /// Literal string search (fastest for simple cases)
    LiteralSearch {
        literals: Vec<String>,
        case_sensitive: bool,
    },
    /// Pre-validated regex pattern
    Regex { pattern: String },
    /// AST walker for complex patterns (single pattern with metavariables)
    AstWalker {
        pattern: String,
        metavariables: Vec<String>,
    },
    /// Compound pattern match (patterns + pattern-inside + metavariable-regex etc.)
    /// Preserves the full structure of Semgrep `patterns:` arrays.
    CompoundMatch {
        /// Main patterns that must match (from `pattern:` clauses)
        patterns: Vec<String>,
        /// Alternative patterns from `pattern-either:` (any must match)
        patterns_either: Vec<String>,
        /// Context constraints from `pattern-inside:` (checked against whole file, AND)
        patterns_inside: Vec<String>,
        /// Context constraints where ANY must match (OR), e.g. from pattern-either
        /// containing pattern-inside entries
        patterns_inside_any: Vec<String>,
        /// Negative constraints from `pattern-not:`
        patterns_not: Vec<String>,
        /// Negative context from `pattern-not-inside:` (checked against whole file)
        patterns_not_inside: Vec<String>,
        /// Regex patterns from `pattern-regex:`
        pattern_regex: Vec<String>,
        /// Metavariable regex constraints: (metavariable_name, regex_pattern)
        metavariable_regex: Vec<(String, String)>,
        /// Extracted metavariable names
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

    /// Security subcategory (vuln, audit, style) — normalized from YAML
    subcategory: Option<Vec<String>>,
    /// Technology tags from rule metadata
    technology: Option<Vec<String>>,
    /// Impact level (HIGH/MEDIUM/LOW)
    impact: Option<String>,
    /// Likelihood level (HIGH/MEDIUM/LOW)
    likelihood: Option<String>,
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
    #[serde(default)]
    subcategory: Option<Vec<String>>,
    #[serde(default)]
    technology: Option<Vec<String>>,
    #[serde(default)]
    impact: Option<String>,
    #[serde(default)]
    likelihood: Option<String>,
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

    // Normalize subcategory to canonical buckets
    let subcategory = metadata.subcategory.map(|subs| {
        subs.into_iter()
            .map(|s| {
                match s.to_lowercase().as_str() {
                    "vuln" | "vulnerability" => "vuln".to_string(),
                    "audit" | "hardening" | "security-audit" => "audit".to_string(),
                    "best-practice" | "best-practices" | "style" => "style".to_string(),
                    other => other.to_lowercase(),
                }
            })
            .collect()
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
        subcategory,
        technology: metadata.technology,
        impact: metadata.impact,
        likelihood: metadata.likelihood,
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
        return MatchStrategy::TreeSitterQuery {
            query,
            captures,
            original_pattern: Some(pattern.to_string()),
        };
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

/// Compile complex patterns array — extracts ALL clause types into a CompoundMatch.
///
/// A Semgrep `patterns:` array uses AND semantics: all clauses must be satisfied.
/// Each clause can be a `pattern`, `pattern-inside`, `pattern-not`, `pattern-either`,
/// `metavariable-regex`, etc. Previously, this function would find the first complex
/// clause and return only its `pattern-inside` as the main pattern, silently dropping
/// all other clauses. This caused massive false positive rates on compound rules.
fn compile_complex_patterns(patterns: &[PatternClause], languages: &[String]) -> MatchStrategy {
    let mut main_patterns: Vec<String> = Vec::new();
    let mut either_patterns: Vec<String> = Vec::new();
    let mut inside_patterns: Vec<String> = Vec::new();
    let mut inside_any_patterns: Vec<String> = Vec::new();
    let mut not_patterns: Vec<String> = Vec::new();
    let mut not_inside_patterns: Vec<String> = Vec::new();
    let mut regex_patterns: Vec<String> = Vec::new();
    let mut metavar_regex: Vec<(String, String)> = Vec::new();
    let mut metavariables: Vec<String> = Vec::new();

    for clause in patterns {
        match clause {
            PatternClause::Simple(s) => {
                main_patterns.push(s.clone());
                metavariables.extend(extract_metavariables(s));
            }
            PatternClause::Complex(map) => {
                // Extract pattern
                if let Some(p) = map.get("pattern").and_then(|v| v.as_str()) {
                    main_patterns.push(p.to_string());
                    metavariables.extend(extract_metavariables(p));
                }

                // Extract pattern-inside
                if let Some(p) = map.get("pattern-inside").and_then(|v| v.as_str()) {
                    inside_patterns.push(p.to_string());
                }

                // Extract pattern-not
                if let Some(p) = map.get("pattern-not").and_then(|v| v.as_str()) {
                    not_patterns.push(p.to_string());
                }

                // Extract pattern-not-inside
                if let Some(p) = map.get("pattern-not-inside").and_then(|v| v.as_str()) {
                    not_inside_patterns.push(p.to_string());
                }

                // Extract pattern-regex
                if let Some(p) = map.get("pattern-regex").and_then(|v| v.as_str()) {
                    // Validate regex at build time
                    if regex::Regex::new(p).is_ok() {
                        regex_patterns.push(p.to_string());
                    }
                }

                // Extract metavariable-regex
                if let Some(mv) = map.get("metavariable-regex") {
                    let var = mv
                        .get("metavariable")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let re = mv
                        .get("regex")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if let (Some(var), Some(re)) = (var, re) {
                        // Validate regex at build time
                        if regex::Regex::new(&re).is_ok() {
                            metavar_regex.push((var, re));
                        }
                    }
                }

                // Extract pattern-either (nested OR within AND)
                if let Some(either) = map.get("pattern-either") {
                    if let Some(arr) = either.as_sequence() {
                        extract_either_patterns(
                            arr,
                            &mut either_patterns,
                            &mut inside_any_patterns,
                            &mut metavariables,
                        );
                    }
                }
            }
        }
    }

    // If we have nothing useful, skip the rule
    if main_patterns.is_empty() && either_patterns.is_empty() && regex_patterns.is_empty() {
        return MatchStrategy::Skipped {
            reason: "Could not extract usable pattern from compound rule".to_string(),
        };
    }

    // Optimization: if there are no context constraints and only a single simple pattern,
    // use the simpler AstWalker strategy
    if inside_patterns.is_empty()
        && inside_any_patterns.is_empty()
        && not_inside_patterns.is_empty()
        && metavar_regex.is_empty()
        && not_patterns.is_empty()
        && regex_patterns.is_empty()
        && either_patterns.is_empty()
        && main_patterns.len() == 1
    {
        return translate_pattern(&main_patterns[0], languages);
    }

    MatchStrategy::CompoundMatch {
        patterns: main_patterns,
        patterns_either: either_patterns,
        patterns_inside: inside_patterns,
        patterns_inside_any: inside_any_patterns,
        patterns_not: not_patterns,
        patterns_not_inside: not_inside_patterns,
        pattern_regex: regex_patterns,
        metavariable_regex: metavar_regex,
        metavariables,
    }
}

/// Extract patterns from a pattern-either sequence (nested within a patterns array).
/// Handles simple string alternatives, {pattern: "..."}, {pattern-inside: "..."}, and
/// nested {patterns: [...]} maps.
///
/// When `pattern-either` contains `pattern-inside` items, these become OR'd context
/// constraints (any of them must match), stored in `inside_any_patterns`.
fn extract_either_patterns(
    arr: &[serde_yaml::Value],
    either_patterns: &mut Vec<String>,
    inside_any_patterns: &mut Vec<String>,
    metavariables: &mut Vec<String>,
) {
    for item in arr {
        // Simple string alternative
        if let Some(s) = item.as_str() {
            either_patterns.push(s.to_string());
            metavariables.extend(extract_metavariables(s));
            continue;
        }

        // Mapping alternative
        if let Some(map) = item.as_mapping() {
            // {pattern-inside: "..."} — OR'd context constraint
            if let Some(p) = map
                .get(&serde_yaml::Value::String("pattern-inside".to_string()))
                .and_then(|v| v.as_str())
            {
                inside_any_patterns.push(p.to_string());
                continue;
            }

            // Direct {pattern: "..."} alternative
            if let Some(p) = map
                .get(&serde_yaml::Value::String("pattern".to_string()))
                .and_then(|v| v.as_str())
            {
                either_patterns.push(p.to_string());
                metavariables.extend(extract_metavariables(p));
            }

            // Nested {patterns: [...]} group — extract leaf patterns
            if let Some(nested) = map
                .get(&serde_yaml::Value::String("patterns".to_string()))
                .and_then(|v| v.as_sequence())
            {
                for nested_item in nested {
                    if let Some(s) = nested_item.as_str() {
                        either_patterns.push(s.to_string());
                        metavariables.extend(extract_metavariables(s));
                    } else if let Some(nm) = nested_item.as_mapping() {
                        if let Some(p) = nm
                            .get(&serde_yaml::Value::String("pattern".to_string()))
                            .and_then(|v| v.as_str())
                        {
                            either_patterns.push(p.to_string());
                            metavariables.extend(extract_metavariables(p));
                        }
                    }
                }
            }
        }
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

    // Member access: $X.password, $OBJ.$ATTR
    if let Some(query) = translate_member_access_pattern(pattern, lang) {
        return Some(query);
    }

    // Index/subscript: $X[$Y]
    if let Some(query) = translate_index_pattern(pattern, lang) {
        return Some(query);
    }

    // Binary operator: $X + $Y, $X == $Y
    if let Some(query) = translate_binary_op_pattern(pattern, lang) {
        return Some(query);
    }

    // Import patterns: require('...'), import ..., from X import Y
    if let Some(query) = translate_import_pattern(pattern, lang) {
        return Some(query);
    }

    // Return statements: return $X
    if let Some(query) = translate_return_pattern(pattern, lang) {
        return Some(query);
    }

    // Conditionals: if $COND: ...
    if let Some(query) = translate_conditional_pattern(pattern, lang) {
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

/// Translate member access patterns like `$X.password` or `$OBJ.secret_key`
///
/// Handles both literal member names (e.g., `$X.password`) where we match
/// the attribute name exactly, and generic access (`$X.$Y`) where we match
/// any attribute access.
fn translate_member_access_pattern(pattern: &str, lang: &str) -> Option<String> {
    // Match: $VAR.identifier (literal member) or $VAR.$VAR (generic access)
    let member_re = regex::Regex::new(r"^\$\w+\.(\$?\w+)$").ok()?;
    let caps = member_re.captures(pattern.trim())?;
    let member = caps.get(1)?.as_str();

    // If member is a metavariable ($Y), match any attribute access
    let is_metavar = member.starts_with('$');

    let query = match lang {
        "python" => {
            if is_metavar {
                r#"(attribute object: (_) @obj attribute: (identifier) @attr)"#.to_string()
            } else {
                format!(
                    r#"(attribute object: (_) @obj attribute: (identifier) @attr (#eq? @attr "{}"))"#,
                    member
                )
            }
        }
        "javascript" | "typescript" => {
            if is_metavar {
                r#"(member_expression object: (_) @obj property: (property_identifier) @prop)"#
                    .to_string()
            } else {
                format!(
                    r#"(member_expression object: (_) @obj property: (property_identifier) @prop (#eq? @prop "{}"))"#,
                    member
                )
            }
        }
        "java" => {
            if is_metavar {
                r#"(field_access object: (_) @obj field: (identifier) @field)"#.to_string()
            } else {
                format!(
                    r#"(field_access object: (_) @obj field: (identifier) @field (#eq? @field "{}"))"#,
                    member
                )
            }
        }
        "go" => {
            if is_metavar {
                r#"(selector_expression operand: (_) @obj field: (field_identifier) @field)"#
                    .to_string()
            } else {
                format!(
                    r#"(selector_expression operand: (_) @obj field: (field_identifier) @field (#eq? @field "{}"))"#,
                    member
                )
            }
        }
        _ => return None,
    };

    Some(query)
}

/// Translate index/subscript patterns like `$X[$Y]` or `$DICT["key"]`
///
/// Matches array/dict subscript access for languages with subscript node types.
fn translate_index_pattern(pattern: &str, lang: &str) -> Option<String> {
    // Match: $VAR[$...] or $VAR["literal"] or identifier[$...]
    let index_re = regex::Regex::new(r"^(\$?\w+)\[(.+)\]$").ok()?;
    let caps = index_re.captures(pattern.trim())?;
    let _obj = caps.get(1)?.as_str();
    let index_expr = caps.get(2)?.as_str();

    // If index is a string literal, add a match predicate
    let is_string_literal = index_expr.starts_with('"') && index_expr.ends_with('"');

    let query = match lang {
        "python" => {
            if is_string_literal {
                let inner = &index_expr[1..index_expr.len() - 1];
                format!(
                    r#"(subscript value: (_) @obj subscript: (string) @key (#match? @key "{}"))"#,
                    inner
                )
            } else {
                r#"(subscript value: (_) @obj subscript: (_) @key)"#.to_string()
            }
        }
        "javascript" | "typescript" => {
            if is_string_literal {
                let inner = &index_expr[1..index_expr.len() - 1];
                format!(
                    r#"(subscript_expression object: (_) @obj index: (string) @key (#match? @key "{}"))"#,
                    inner
                )
            } else {
                r#"(subscript_expression object: (_) @obj index: (_) @key)"#.to_string()
            }
        }
        "java" => {
            // Java uses array_access
            r#"(array_access array: (_) @obj index: (_) @key)"#.to_string()
        }
        _ => return None,
    };

    Some(query)
}

/// Translate binary operator patterns like `$X + $Y`, `$X == $Y`
///
/// Matches binary expressions with specific operators. The operator is matched
/// literally from the pattern.
fn translate_binary_op_pattern(pattern: &str, lang: &str) -> Option<String> {
    // Match: $VAR op $VAR — supports common operators
    let bin_re =
        regex::Regex::new(r"^(\$\w+)\s*(==|!=|<=|>=|<|>|\+|-|\*|/|%|\|\||&&|and|or|in|not\s+in)\s*(\$\w+)$")
            .ok()?;
    let caps = bin_re.captures(pattern.trim())?;
    let _lhs = caps.get(1)?.as_str();
    let op = caps.get(2)?.as_str();
    let _rhs = caps.get(3)?.as_str();

    let query = match lang {
        "python" => {
            match op {
                "in" | "not in" => {
                    // Python uses comparison_operator for `in` / `not in`
                    r#"(comparison_operator (_) @lhs (_) @rhs)"#.to_string()
                }
                "and" | "or" => {
                    format!(
                        r#"(boolean_operator left: (_) @lhs operator: "{}" right: (_) @rhs)"#,
                        op
                    )
                }
                _ => {
                    format!(
                        r#"(binary_operator left: (_) @lhs operator: "{}" right: (_) @rhs)"#,
                        op
                    )
                }
            }
        }
        "javascript" | "typescript" => {
            format!(
                r#"(binary_expression left: (_) @lhs operator: "{}" right: (_) @rhs)"#,
                op
            )
        }
        _ => return None,
    };

    Some(query)
}

/// Translate import patterns like `require('...')`, `import ...`, `from X import Y`
///
/// Handles:
/// - JS/TS: `require("module")` or `require('module')`
/// - Python: `import module`, `from module import name`
/// - Go: `import "module"`
fn translate_import_pattern(pattern: &str, lang: &str) -> Option<String> {
    let trimmed = pattern.trim();

    // JS/TS: require("module") or require('module')
    let require_re = regex::Regex::new(r#"^require\(\s*['"](.+)['"]\s*\)$"#).ok()?;
    if let Some(caps) = require_re.captures(trimmed) {
        let module = caps.get(1)?.as_str();
        return match lang {
            "javascript" | "typescript" => Some(format!(
                r#"(call_expression function: (identifier) @func (#eq? @func "require") arguments: (arguments (string) @mod (#match? @mod "{}")))"#,
                regex::escape(module)
            )),
            _ => None,
        };
    }

    // Python: from $MODULE import $NAME or from module import name
    let from_import_re = regex::Regex::new(r"^from\s+(\S+)\s+import\s+(\S+)$").ok()?;
    if let Some(caps) = from_import_re.captures(trimmed) {
        let module = caps.get(1)?.as_str();
        let name = caps.get(2)?.as_str();
        let is_module_meta = module.starts_with('$');
        let is_name_meta = name.starts_with('$');

        return match lang {
            "python" => {
                if is_module_meta && is_name_meta {
                    Some(
                        r#"(import_from_statement module_name: (dotted_name) @mod name: (dotted_name) @name)"#
                            .to_string(),
                    )
                } else if is_module_meta {
                    Some(format!(
                        r#"(import_from_statement module_name: (dotted_name) @mod name: (dotted_name) @name (#match? @name "{}"))"#,
                        regex::escape(name)
                    ))
                } else if is_name_meta {
                    Some(format!(
                        r#"(import_from_statement module_name: (dotted_name) @mod (#match? @mod "{}") name: (dotted_name) @name)"#,
                        regex::escape(module)
                    ))
                } else {
                    Some(format!(
                        r#"(import_from_statement module_name: (dotted_name) @mod (#match? @mod "{}") name: (dotted_name) @name (#match? @name "{}"))"#,
                        regex::escape(module),
                        regex::escape(name)
                    ))
                }
            }
            _ => None,
        };
    }

    // Simple import: import $MODULE or import module
    let import_re = regex::Regex::new(r"^import\s+(\S+)$").ok()?;
    if let Some(caps) = import_re.captures(trimmed) {
        let module = caps.get(1)?.as_str();
        let is_meta = module.starts_with('$');

        return match lang {
            "python" => {
                if is_meta {
                    Some(r#"(import_statement name: (dotted_name) @mod)"#.to_string())
                } else {
                    Some(format!(
                        r#"(import_statement name: (dotted_name) @mod (#match? @mod "{}"))"#,
                        regex::escape(module)
                    ))
                }
            }
            "go" => {
                if is_meta {
                    Some(r#"(import_declaration (import_spec path: (interpreted_string_literal) @mod))"#.to_string())
                } else {
                    Some(format!(
                        r#"(import_declaration (import_spec path: (interpreted_string_literal) @mod (#match? @mod "{}")))"#,
                        regex::escape(module)
                    ))
                }
            }
            _ => None,
        };
    }

    None
}

/// Translate return statement patterns like `return $X` or `return None`
///
/// Matches return statements across languages. When the value is a metavariable,
/// matches any return; when literal, adds a predicate.
fn translate_return_pattern(pattern: &str, lang: &str) -> Option<String> {
    let return_re = regex::Regex::new(r"^return\s+(.+)$").ok()?;
    let caps = return_re.captures(pattern.trim())?;
    let value = caps.get(1)?.as_str().trim();
    let is_meta = value.starts_with('$');

    let query = match lang {
        "python" => {
            if is_meta {
                r#"(return_statement (_) @val) @ret"#.to_string()
            } else {
                format!(
                    r#"(return_statement (_) @val (#match? @val "{}")) @ret"#,
                    regex::escape(value)
                )
            }
        }
        "javascript" | "typescript" => {
            if is_meta {
                r#"(return_statement (_) @val) @ret"#.to_string()
            } else {
                format!(
                    r#"(return_statement (_) @val (#match? @val "{}")) @ret"#,
                    regex::escape(value)
                )
            }
        }
        "java" => {
            if is_meta {
                r#"(return_statement (_) @val) @ret"#.to_string()
            } else {
                format!(
                    r#"(return_statement (_) @val (#match? @val "{}")) @ret"#,
                    regex::escape(value)
                )
            }
        }
        "go" => {
            if is_meta {
                r#"(return_statement (expression_list (_) @val)) @ret"#.to_string()
            } else {
                format!(
                    r#"(return_statement (expression_list (_) @val (#match? @val "{}"))) @ret"#,
                    regex::escape(value)
                )
            }
        }
        "rust" => {
            if is_meta {
                r#"(return_expression (_) @val) @ret"#.to_string()
            } else {
                format!(
                    r#"(return_expression (_) @val (#match? @val "{}")) @ret"#,
                    regex::escape(value)
                )
            }
        }
        _ => return None,
    };

    Some(query)
}

/// Translate conditional patterns like `if $COND: ...` or `if ($COND) { ... }`
///
/// Matches if-statements, capturing the condition for further analysis.
fn translate_conditional_pattern(pattern: &str, lang: &str) -> Option<String> {
    // Match: if (...) or if $COND:
    let if_re = regex::Regex::new(r"^if\s+(.+?)(\s*:|\s*\{|$)").ok()?;
    let _caps = if_re.captures(pattern.trim())?;

    let query = match lang {
        "python" => {
            r#"(if_statement condition: (_) @cond) @if"#.to_string()
        }
        "javascript" | "typescript" => {
            r#"(if_statement condition: (parenthesized_expression (_) @cond)) @if"#.to_string()
        }
        "java" => {
            r#"(if_statement condition: (parenthesized_expression (_) @cond)) @if"#.to_string()
        }
        "go" => {
            r#"(if_statement condition: (_) @cond) @if"#.to_string()
        }
        "rust" => {
            r#"(if_expression condition: (_) @cond) @if"#.to_string()
        }
        _ => return None,
    };

    Some(query)
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
            .map(|s| s.to_string()),
        // NOTE: Previously fell back to "pattern-inside" which caused
        // context patterns to be treated as main patterns, generating
        // massive false positives on compound rules.
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

    // Also extract from compound patterns array
    if let Some(ref patterns) = raw.patterns {
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
