//! Rule matcher - applies rules to source code and generates findings

use crate::{pattern::PatternMatcher, PatternClause, PatternOperator, Result, Rule};
use rma_common::{Finding, FindingCategory, Language, SourceLocation};
use std::path::Path;

/// A compiled rule ready for matching
#[derive(Debug)]
pub struct CompiledRule {
    /// Original rule definition
    pub rule: Rule,

    /// Compiled pattern matcher
    pub matcher: PatternMatcher,

    /// Whether this is a taint rule
    pub is_taint: bool,

    /// Taint sources (for taint mode)
    pub sources: Vec<PatternMatcher>,

    /// Taint sinks (for taint mode)
    pub sinks: Vec<PatternMatcher>,

    /// Taint sanitizers (for taint mode)
    pub sanitizers: Vec<PatternMatcher>,
}

impl CompiledRule {
    /// Compile a rule for matching
    pub fn compile(rule: Rule) -> Result<Self> {
        let mut matcher = PatternMatcher::new();
        let is_taint = rule.is_taint_mode();

        // Compile main pattern
        if let Some(ref pattern) = rule.pattern {
            matcher.add_pattern(pattern)?;
        }

        // Compile pattern-either
        if let Some(ref patterns) = rule.pattern_either {
            for clause in patterns {
                compile_pattern_clause(&mut matcher, clause, true)?;
            }
        }

        // Compile patterns (AND)
        if let Some(ref patterns) = rule.patterns {
            for clause in patterns {
                compile_pattern_clause(&mut matcher, clause, false)?;
            }
        }

        // Compile pattern-not
        if let Some(ref pattern) = rule.pattern_not {
            matcher.add_pattern_not(pattern)?;
        }

        // Compile pattern-regex
        if let Some(ref regex) = rule.pattern_regex {
            matcher.add_regex(regex)?;
        }

        // Compile taint patterns
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut sanitizers = Vec::new();

        if let Some(ref source_patterns) = rule.pattern_sources {
            for clause in source_patterns {
                let mut source_matcher = PatternMatcher::new();
                compile_pattern_clause(&mut source_matcher, clause, false)?;
                sources.push(source_matcher);
            }
        }

        if let Some(ref sink_patterns) = rule.pattern_sinks {
            for clause in sink_patterns {
                let mut sink_matcher = PatternMatcher::new();
                compile_pattern_clause(&mut sink_matcher, clause, false)?;
                sinks.push(sink_matcher);
            }
        }

        if let Some(ref sanitizer_patterns) = rule.pattern_sanitizers {
            for clause in sanitizer_patterns {
                let mut sanitizer_matcher = PatternMatcher::new();
                compile_pattern_clause(&mut sanitizer_matcher, clause, false)?;
                sanitizers.push(sanitizer_matcher);
            }
        }

        Ok(Self {
            rule,
            matcher,
            is_taint,
            sources,
            sinks,
            sanitizers,
        })
    }

    /// Check if this rule applies to the given language
    pub fn applies_to(&self, lang: &str) -> bool {
        self.rule.applies_to(lang)
    }

    /// Check source code and return findings
    pub fn check(&self, code: &str, path: &Path, language: Language) -> Vec<Finding> {
        let mut findings = Vec::new();

        if self.is_taint {
            findings.extend(self.check_taint(code, path, language));
        } else {
            findings.extend(self.check_patterns(code, path, language));
        }

        findings
    }

    /// Check with regular pattern matching
    fn check_patterns(&self, code: &str, path: &Path, language: Language) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in code.lines().enumerate() {
            if self.matcher.matches(line) {
                let finding = self.create_finding(path, line_num + 1, line.trim(), language);
                findings.push(finding);
            }
        }

        let multi_matches = self.matcher.find_matches(code);
        for m in multi_matches {
            let line_num = code[..m.start].matches('\n').count() + 1;
            let line = code.lines().nth(line_num - 1).unwrap_or(&m.text);

            if !findings.iter().any(|f| f.location.start_line == line_num) {
                let finding = self.create_finding(path, line_num, line.trim(), language);
                findings.push(finding);
            }
        }

        findings
    }

    /// Check with taint mode (simplified)
    fn check_taint(&self, code: &str, path: &Path, language: Language) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (line_num, line) in code.lines().enumerate() {
            let is_sink = self.sinks.iter().any(|s| s.matches(line));

            if is_sink {
                let is_sanitized = self.sanitizers.iter().any(|s| s.matches(line));

                if !is_sanitized {
                    let has_source = self.sources.iter().any(|s| s.matches(code));

                    if has_source {
                        let finding =
                            self.create_finding(path, line_num + 1, line.trim(), language);
                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }

    /// Create a finding from a match
    fn create_finding(
        &self,
        path: &Path,
        line: usize,
        snippet: &str,
        language: Language,
    ) -> Finding {
        let mut finding = Finding {
            id: format!("{}-{}-1", self.rule.id, line),
            rule_id: self.rule.id.clone(),
            message: self.rule.message.clone(),
            severity: self.rule.severity.into(),
            location: SourceLocation::new(path.to_path_buf(), line, 1, line, snippet.len()),
            language,
            snippet: Some(snippet.to_string()),
            suggestion: self.rule.fix.clone(),
            fix: None,
            confidence: self.rule.confidence(),
            category: infer_category(&self.rule),
            fingerprint: None,
            properties: None,
            occurrence_count: None,
            additional_locations: None,
        };

        finding.compute_fingerprint();
        finding
    }
}

/// Compile a pattern clause into a pattern matcher
fn compile_pattern_clause(
    matcher: &mut PatternMatcher,
    clause: &PatternClause,
    is_either: bool,
) -> Result<()> {
    match clause {
        PatternClause::Simple(pattern) => {
            if is_either {
                matcher.add_pattern_either(pattern)?;
            } else {
                matcher.add_pattern(pattern)?;
            }
        }
        PatternClause::Complex(op) => {
            compile_pattern_operator(matcher, op, is_either)?;
        }
    }
    Ok(())
}

/// Compile a pattern operator
fn compile_pattern_operator(
    matcher: &mut PatternMatcher,
    op: &PatternOperator,
    is_either: bool,
) -> Result<()> {
    if let Some(ref pattern) = op.pattern {
        if is_either {
            matcher.add_pattern_either(pattern)?;
        } else {
            matcher.add_pattern(pattern)?;
        }
    }

    if let Some(ref patterns) = op.pattern_either {
        for clause in patterns {
            compile_pattern_clause(matcher, clause, true)?;
        }
    }

    if let Some(ref patterns) = op.patterns {
        for clause in patterns {
            compile_pattern_clause(matcher, clause, false)?;
        }
    }

    if let Some(ref pattern) = op.pattern_not {
        matcher.add_pattern_not(pattern)?;
    }

    if let Some(ref pattern) = op.pattern_inside {
        matcher.add_pattern_inside(pattern)?;
    }

    if let Some(ref regex) = op.pattern_regex {
        matcher.add_regex(regex)?;
    }

    Ok(())
}

/// Infer the finding category from the rule
fn infer_category(rule: &Rule) -> FindingCategory {
    let category = rule.category().to_lowercase();

    if category.contains("security") {
        return FindingCategory::Security;
    }
    if category.contains("performance") {
        return FindingCategory::Performance;
    }
    if category.contains("correctness") || category.contains("bug") || category.contains("quality")
    {
        return FindingCategory::Quality;
    }
    if category.contains("style")
        || category.contains("best-practice")
        || category.contains("compatibility")
    {
        return FindingCategory::Style;
    }

    if rule.metadata.cwe.is_some() {
        return FindingCategory::Security;
    }

    if let Some(ref subcats) = rule.metadata.subcategory {
        if subcats.iter().any(|s| s == "vuln" || s == "audit") {
            return FindingCategory::Security;
        }
    }

    FindingCategory::Security
}

/// Rule runner that applies multiple rules to code
pub struct RuleRunner {
    rules: Vec<CompiledRule>,
}

impl RuleRunner {
    /// Create a new rule runner from rules
    pub fn new(rules: Vec<Rule>) -> Result<Self> {
        let compiled: Result<Vec<CompiledRule>> =
            rules.into_iter().map(CompiledRule::compile).collect();

        Ok(Self { rules: compiled? })
    }

    /// Get the number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get rules for a specific language
    pub fn rules_for_language(&self, lang: &str) -> Vec<&CompiledRule> {
        self.rules.iter().filter(|r| r.applies_to(lang)).collect()
    }

    /// Run all applicable rules on code
    pub fn check(&self, code: &str, path: &Path, language: Language) -> Vec<Finding> {
        let lang_str = language.to_string().to_lowercase();
        let mut findings = Vec::new();

        for rule in &self.rules {
            if rule.applies_to(&lang_str) {
                findings.extend(rule.check(code, path, language));
            }
        }

        findings
    }

    /// Run rules in parallel (for multiple files)
    pub fn check_parallel(&self, files: &[(String, &Path, Language)]) -> Vec<Finding> {
        use rayon::prelude::*;

        files
            .par_iter()
            .flat_map(|(code, path, lang)| self.check(code, path, *lang))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_rule(id: &str, pattern: &str, languages: Vec<&str>) -> Rule {
        Rule {
            id: id.to_string(),
            message: format!("Test rule: {}", id),
            severity: crate::format::Severity::Warning,
            languages: languages.into_iter().map(String::from).collect(),
            mode: crate::format::RuleMode::Search,
            pattern: Some(pattern.to_string()),
            pattern_either: None,
            patterns: None,
            pattern_not: None,
            pattern_regex: None,
            pattern_sources: None,
            pattern_sinks: None,
            pattern_sanitizers: None,
            pattern_propagators: None,
            metadata: crate::format::RuleMetadata::default(),
            fix: None,
            fix_regex: None,
            min_version: None,
            options: None,
        }
    }

    #[test]
    fn test_compiled_rule_matches() {
        let rule = create_test_rule("test-print", "print($MSG)", vec!["python"]);
        let compiled = CompiledRule::compile(rule).unwrap();

        let code = "print(hello)";
        let findings = compiled.check(code, Path::new("test.py"), Language::Python);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "test-print");
    }

    #[test]
    fn test_rule_runner() {
        let rules = vec![
            create_test_rule("py-print", "print($X)", vec!["python"]),
            create_test_rule("js-log", "console.log($X)", vec!["javascript"]),
        ];

        let runner = RuleRunner::new(rules).unwrap();
        assert_eq!(runner.rule_count(), 2);
        assert_eq!(runner.rules_for_language("python").len(), 1);
    }
}
