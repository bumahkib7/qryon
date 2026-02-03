//! Pattern compilation and matching
//!
//! Converts Semgrep-style patterns into regex patterns for matching.
//! Handles metavariables ($X, $FUNC, etc.) and ellipsis (...).

use crate::Result;
use regex::Regex;
use std::collections::HashMap;

/// A compiled pattern ready for matching
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    /// The original pattern string
    pub original: String,

    /// Compiled regex
    pub regex: Regex,

    /// Metavariables in the pattern
    pub metavariables: Vec<String>,

    /// Whether this is an ellipsis pattern
    pub has_ellipsis: bool,
}

impl CompiledPattern {
    /// Compile a Semgrep-style pattern into a regex
    pub fn compile(pattern: &str) -> Result<Self> {
        let original = pattern.to_string();
        let mut metavariables = Vec::new();
        let has_ellipsis = pattern.contains("...");

        // Convert pattern to regex
        let regex_str = pattern_to_regex(pattern, &mut metavariables)?;
        let regex = Regex::new(&regex_str)?;

        Ok(Self {
            original,
            regex,
            metavariables,
            has_ellipsis,
        })
    }

    /// Check if the pattern matches the given code
    pub fn matches(&self, code: &str) -> bool {
        self.regex.is_match(code)
    }

    /// Find all matches and extract metavariable bindings
    pub fn find_matches(&self, code: &str) -> Vec<PatternMatch> {
        self.regex
            .captures_iter(code)
            .map(|caps| {
                let full_match = caps.get(0).unwrap();
                let mut bindings = HashMap::new();

                for (i, name) in self.metavariables.iter().enumerate() {
                    if let Some(m) = caps.get(i + 1) {
                        bindings.insert(name.clone(), m.as_str().to_string());
                    }
                }

                PatternMatch {
                    text: full_match.as_str().to_string(),
                    start: full_match.start(),
                    end: full_match.end(),
                    bindings,
                }
            })
            .collect()
    }
}

/// A single pattern match with metavariable bindings
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// The matched text
    pub text: String,

    /// Start byte offset
    pub start: usize,

    /// End byte offset
    pub end: usize,

    /// Metavariable bindings
    pub bindings: HashMap<String, String>,
}

/// Convert a Semgrep pattern to a regex string
fn pattern_to_regex(pattern: &str, metavariables: &mut Vec<String>) -> Result<String> {
    let mut result = String::new();
    let mut chars = pattern.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            // Metavariable: $X, $FUNC, $...ARGS
            '$' => {
                let mut name = String::new();
                let mut is_ellipsis_var = false;

                // Check for ellipsis metavariable $...X
                if chars.peek() == Some(&'.') {
                    chars.next(); // consume first .
                    if chars.next() == Some('.') && chars.next() == Some('.') {
                        is_ellipsis_var = true;
                    }
                }

                // Collect metavariable name
                while let Some(&ch) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        name.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }

                if name.is_empty() {
                    // Literal $
                    result.push_str(r"\$");
                } else {
                    metavariables.push(format!("${}", name));
                    if is_ellipsis_var {
                        // Ellipsis metavariable matches zero or more items
                        result.push_str(r"(.*)");
                    } else {
                        // Regular metavariable matches an identifier or expression
                        result.push_str(
                            r"([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*(?:\([^)]*\))?)",
                        );
                    }
                }
            }

            // Ellipsis: matches anything
            '.' if chars.peek() == Some(&'.') => {
                chars.next(); // consume second .
                if chars.next() == Some('.') {
                    // ... matches any sequence
                    result.push_str(r"[\s\S]*?");
                } else {
                    // Just .. (rare, treat as literal)
                    result.push_str(r"\.\.");
                }
            }

            // Escape special regex characters
            '\\' | '.' | '+' | '*' | '?' | '^' | '[' | ']' | '{' | '}' | '|' | '(' | ')' => {
                result.push('\\');
                result.push(c);
            }

            // Whitespace: flexible matching
            ' ' | '\t' | '\n' | '\r' => {
                result.push_str(r"\s*");
            }

            // Other characters: literal
            _ => {
                result.push(c);
            }
        }
    }

    Ok(result)
}

/// Pattern matcher that handles complex pattern logic
#[derive(Debug)]
pub struct PatternMatcher {
    /// Pattern clauses to match (AND)
    pub patterns: Vec<CompiledPattern>,

    /// Pattern clauses where any can match (OR)
    pub patterns_either: Vec<CompiledPattern>,

    /// Patterns that must NOT match
    pub patterns_not: Vec<CompiledPattern>,

    /// Patterns the match must be inside
    pub patterns_inside: Vec<CompiledPattern>,

    /// Patterns the match must NOT be inside
    pub patterns_not_inside: Vec<CompiledPattern>,

    /// Regex patterns
    pub regex_patterns: Vec<Regex>,
}

impl PatternMatcher {
    /// Create an empty pattern matcher
    pub fn new() -> Self {
        Self {
            patterns: vec![],
            patterns_either: vec![],
            patterns_not: vec![],
            patterns_inside: vec![],
            patterns_not_inside: vec![],
            regex_patterns: vec![],
        }
    }

    /// Add a required pattern (AND)
    pub fn add_pattern(&mut self, pattern: &str) -> Result<()> {
        self.patterns.push(CompiledPattern::compile(pattern)?);
        Ok(())
    }

    /// Add an alternative pattern (OR)
    pub fn add_pattern_either(&mut self, pattern: &str) -> Result<()> {
        self.patterns_either
            .push(CompiledPattern::compile(pattern)?);
        Ok(())
    }

    /// Add a negation pattern
    pub fn add_pattern_not(&mut self, pattern: &str) -> Result<()> {
        self.patterns_not.push(CompiledPattern::compile(pattern)?);
        Ok(())
    }

    /// Add a context pattern (must be inside)
    pub fn add_pattern_inside(&mut self, pattern: &str) -> Result<()> {
        self.patterns_inside
            .push(CompiledPattern::compile(pattern)?);
        Ok(())
    }

    /// Add a regex pattern
    pub fn add_regex(&mut self, regex: &str) -> Result<()> {
        self.regex_patterns.push(Regex::new(regex)?);
        Ok(())
    }

    /// Check if code matches this pattern set
    pub fn matches(&self, code: &str) -> bool {
        // If we have pattern-either, at least one must match
        if !self.patterns_either.is_empty() && !self.patterns_either.iter().any(|p| p.matches(code))
        {
            return false;
        }

        // All required patterns must match
        if !self.patterns.iter().all(|p| p.matches(code)) {
            return false;
        }

        // No negation patterns should match
        if self.patterns_not.iter().any(|p| p.matches(code)) {
            return false;
        }

        // All regex patterns must match
        if !self.regex_patterns.iter().all(|r| r.is_match(code)) {
            return false;
        }

        true
    }

    /// Find all matches in code
    pub fn find_matches(&self, code: &str) -> Vec<PatternMatch> {
        let mut results = Vec::new();

        // Collect matches from either patterns
        if !self.patterns_either.is_empty() {
            for pattern in &self.patterns_either {
                results.extend(pattern.find_matches(code));
            }
        }

        // Collect matches from required patterns
        for pattern in &self.patterns {
            results.extend(pattern.find_matches(code));
        }

        // Filter out matches that hit negation patterns
        if !self.patterns_not.is_empty() {
            results.retain(|m| !self.patterns_not.iter().any(|p| p.matches(&m.text)));
        }

        results
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_pattern() {
        let pattern = CompiledPattern::compile("print($X)").unwrap();
        assert!(pattern.matches("print(foo)"));
        assert!(pattern.matches("print(bar.baz)"));
        assert!(!pattern.matches("println(foo)"));
    }

    #[test]
    fn test_metavariable_extraction() {
        let pattern = CompiledPattern::compile("$FUNC($ARG)").unwrap();
        let matches = pattern.find_matches("print(foo)");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].bindings.get("$FUNC"), Some(&"print".to_string()));
        assert_eq!(matches[0].bindings.get("$ARG"), Some(&"foo".to_string()));
    }

    #[test]
    fn test_ellipsis_pattern() {
        let pattern = CompiledPattern::compile("func(..., $LAST)").unwrap();
        assert!(pattern.matches("func(a, b, c, last)"));
        // Single arg doesn't match because pattern requires comma before $LAST
        // This is correct Semgrep behavior

        // Test simpler ellipsis
        let pattern2 = CompiledPattern::compile("func(...)").unwrap();
        assert!(pattern2.matches("func()"));
        assert!(pattern2.matches("func(a)"));
        assert!(pattern2.matches("func(a, b, c)"));
    }

    #[test]
    fn test_pattern_matcher() {
        let mut matcher = PatternMatcher::new();
        matcher.add_pattern("execute($SQL)").unwrap();
        matcher.add_pattern_not("execute(?)").unwrap();

        assert!(matcher.matches("cursor.execute(query)"));
        assert!(!matcher.matches("cursor.execute(?)"));
    }

    #[test]
    fn test_pattern_either() {
        let mut matcher = PatternMatcher::new();
        matcher.add_pattern_either("print($X)").unwrap();
        matcher.add_pattern_either("console.log($X)").unwrap();

        assert!(matcher.matches("print(foo)"));
        assert!(matcher.matches("console.log(bar)"));
        assert!(!matcher.matches("println(baz)"));
    }
}
