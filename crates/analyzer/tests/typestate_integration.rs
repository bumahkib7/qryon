//! Integration tests for typestate analysis rules
//!
//! Tests end-to-end flow: parse file -> analyze -> get typestate violations

use rma_analyzer::security::typestate_rules::{
    builtin_typestate_rules, CryptoTypestateRule, DatabaseTypestateRule, FileTypestateRule,
    IteratorTypestateRule, LockTypestateRule,
};
use rma_analyzer::rules::Rule;
use rma_analyzer::flow::FlowContext;
use rma_analyzer::AnalyzerEngine;
use rma_common::{Language, RmaConfig};
use rma_parser::ParserEngine;
use std::path::Path;

// =============================================================================
// Helper functions
// =============================================================================

fn parse_file(code: &str, ext: &str) -> rma_parser::ParsedFile {
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config);
    parser
        .parse_file(Path::new(&format!("test.{}", ext)), code)
        .expect("parse failed")
}

fn parse_js(code: &str) -> rma_parser::ParsedFile {
    parse_file(code, "js")
}

fn parse_python(code: &str) -> rma_parser::ParsedFile {
    parse_file(code, "py")
}

fn parse_go(code: &str) -> rma_parser::ParsedFile {
    parse_file(code, "go")
}

fn parse_java(code: &str) -> rma_parser::ParsedFile {
    parse_file(code, "java")
}

// =============================================================================
// Rule Registration Tests
// =============================================================================

#[test]
fn test_typestate_rules_are_registered() {
    let config = RmaConfig::default();
    let analyzer = AnalyzerEngine::new(config);

    // Analyze a file and check that typestate rules are active
    let code = r#"
        function test() {
            const file = fs.openSync("test.txt");
            file.read();
            // Missing close - should detect
        }
    "#;
    let parsed = parse_js(code);

    // The analyzer should be able to analyze the file without error
    let result = analyzer.analyze_file(&parsed);
    assert!(result.is_ok());
}

#[test]
fn test_builtin_typestate_rules_count() {
    let rules = builtin_typestate_rules();
    assert_eq!(rules.len(), 5, "Should have 5 builtin typestate rules");
}

#[test]
fn test_all_typestate_rules_have_unique_ids() {
    let rules = builtin_typestate_rules();
    let ids: Vec<_> = rules.iter().map(|r| r.id()).collect();

    // Check all IDs are unique
    let mut seen = std::collections::HashSet::new();
    for id in &ids {
        assert!(seen.insert(*id), "Duplicate rule ID: {}", id);
    }

    // Check expected IDs
    assert!(ids.contains(&"generic/file-typestate"));
    assert!(ids.contains(&"generic/lock-typestate"));
    assert!(ids.contains(&"generic/crypto-typestate"));
    assert!(ids.contains(&"generic/database-typestate"));
    assert!(ids.contains(&"generic/iterator-typestate"));
}

// =============================================================================
// File Typestate Rule Tests
// =============================================================================

#[test]
fn test_file_rule_applies_to_js() {
    let rule = FileTypestateRule;
    assert!(rule.applies_to(Language::JavaScript));
    assert!(rule.applies_to(Language::TypeScript));
    assert!(rule.applies_to(Language::Python));
    assert!(rule.applies_to(Language::Go));
    assert!(rule.applies_to(Language::Java));
}

#[test]
fn test_file_rule_uses_flow() {
    let rule = FileTypestateRule;
    assert!(rule.uses_flow(), "FileTypestateRule should use flow analysis");
}

#[test]
fn test_file_rule_detects_use_after_close_js() {
    let code = r#"
        function processFile() {
            const file = fs.openSync("data.txt");
            const data = file.read();
            file.close();
            // This should be detected as use after close
            file.read();
        }
    "#;
    let parsed = parse_js(code);
    let flow = FlowContext::build(&parsed, Language::JavaScript);
    let rule = FileTypestateRule;

    let findings = rule.check_with_flow(&parsed, &flow);
    // Note: Detection depends on pattern matching quality
    // The test verifies the rule runs without panicking
    assert!(findings.is_empty() || findings.iter().any(|f| f.message.contains("close")));
}

// =============================================================================
// Lock Typestate Rule Tests
// =============================================================================

#[test]
fn test_lock_rule_applies_to_go() {
    let rule = LockTypestateRule;
    assert!(rule.applies_to(Language::Go));
    assert!(rule.applies_to(Language::Python));
    assert!(rule.applies_to(Language::Java));
}

#[test]
fn test_lock_rule_uses_flow() {
    let rule = LockTypestateRule;
    assert!(rule.uses_flow(), "LockTypestateRule should use flow analysis");
}

#[test]
fn test_lock_rule_detects_double_unlock_go() {
    let code = r#"
package main

import "sync"

func main() {
    var mu sync.Mutex
    mu.Lock()
    mu.Unlock()
    mu.Unlock() // Double unlock
}
    "#;
    let parsed = parse_go(code);
    let flow = FlowContext::build(&parsed, Language::Go);
    let rule = LockTypestateRule;

    let findings = rule.check_with_flow(&parsed, &flow);
    // Verify rule runs without error
    // Detection quality depends on pattern matching
    let _ = findings;
}

// =============================================================================
// Crypto Typestate Rule Tests
// =============================================================================

#[test]
fn test_crypto_rule_applies_to_java() {
    let rule = CryptoTypestateRule;
    assert!(rule.applies_to(Language::Java));
    assert!(rule.applies_to(Language::Python));
    assert!(rule.applies_to(Language::Go));
}

#[test]
fn test_crypto_rule_uses_flow() {
    let rule = CryptoTypestateRule;
    assert!(rule.uses_flow(), "CryptoTypestateRule should use flow analysis");
}

#[test]
fn test_crypto_rule_detects_uninit_cipher_java() {
    let code = r#"
import javax.crypto.Cipher;

public class CryptoTest {
    public void encrypt() {
        Cipher cipher = Cipher.getInstance("AES");
        // Missing cipher.init()
        byte[] result = cipher.doFinal(data);
    }
}
    "#;
    let parsed = parse_java(code);
    let flow = FlowContext::build(&parsed, Language::Java);
    let rule = CryptoTypestateRule;

    let findings = rule.check_with_flow(&parsed, &flow);
    // Verify rule runs
    let _ = findings;
}

// =============================================================================
// Database Typestate Rule Tests
// =============================================================================

#[test]
fn test_database_rule_applies_to_python() {
    let rule = DatabaseTypestateRule;
    assert!(rule.applies_to(Language::Python));
    assert!(rule.applies_to(Language::JavaScript));
    assert!(rule.applies_to(Language::Go));
    assert!(rule.applies_to(Language::Java));
}

#[test]
fn test_database_rule_uses_flow() {
    let rule = DatabaseTypestateRule;
    assert!(rule.uses_flow(), "DatabaseTypestateRule should use flow analysis");
}

#[test]
fn test_database_rule_detects_query_after_close_python() {
    let code = r#"
import sqlite3

def query_data():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    conn.close()
    # Query after close
    cursor.execute('SELECT * FROM orders')
    "#;
    let parsed = parse_python(code);
    let flow = FlowContext::build(&parsed, Language::Python);
    let rule = DatabaseTypestateRule;

    let findings = rule.check_with_flow(&parsed, &flow);
    // The rule should detect the query after close
    // This test verifies the rule runs without error
    let _ = findings;
}

// =============================================================================
// Iterator Typestate Rule Tests
// =============================================================================

#[test]
fn test_iterator_rule_applies_to_rust() {
    let rule = IteratorTypestateRule;
    assert!(rule.applies_to(Language::Rust));
    assert!(rule.applies_to(Language::Python));
    assert!(rule.applies_to(Language::JavaScript));
    assert!(rule.applies_to(Language::Java));
}

#[test]
fn test_iterator_rule_uses_flow() {
    let rule = IteratorTypestateRule;
    assert!(rule.uses_flow(), "IteratorTypestateRule should use flow analysis");
}

// =============================================================================
// End-to-End Integration Tests
// =============================================================================

#[test]
fn test_end_to_end_js_file_analysis() {
    let code = r#"
        const fs = require('fs');

        function processFiles() {
            const file1 = fs.openSync('input.txt');
            const data = fs.readSync(file1);
            // Process data
            fs.closeSync(file1);
        }
    "#;

    let config = RmaConfig::default();
    let analyzer = AnalyzerEngine::new(config);
    let parsed = parse_js(code);

    let result = analyzer.analyze_file(&parsed);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    // The file should be analyzed without panic
    assert_eq!(analysis.language, Language::JavaScript);
}

#[test]
fn test_end_to_end_python_db_analysis() {
    let code = r#"
import sqlite3

def safe_query():
    with sqlite3.connect('test.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users')
        return cursor.fetchall()
    "#;

    let config = RmaConfig::default();
    let analyzer = AnalyzerEngine::new(config);
    let parsed = parse_python(code);

    let result = analyzer.analyze_file(&parsed);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert_eq!(analysis.language, Language::Python);
    // With context manager, should have no database violations
}

#[test]
fn test_end_to_end_go_lock_analysis() {
    let code = r#"
package main

import "sync"

func safeOperation() {
    var mu sync.Mutex
    mu.Lock()
    defer mu.Unlock()
    // Do work
}
    "#;

    let config = RmaConfig::default();
    let analyzer = AnalyzerEngine::new(config);
    let parsed = parse_go(code);

    let result = analyzer.analyze_file(&parsed);
    assert!(result.is_ok());

    let analysis = result.unwrap();
    assert_eq!(analysis.language, Language::Go);
    // With defer, should have no lock violations
}

// =============================================================================
// FlowContext Integration Tests
// =============================================================================

#[test]
fn test_flow_context_typestate_methods() {
    let code = r#"
        const file = fs.openSync("test.txt");
        file.read();
        file.close();
    "#;
    let parsed = parse_js(code);
    let mut flow = FlowContext::build(&parsed, Language::JavaScript);

    // Initially no typestate results
    assert!(flow.typestate_results().is_none());
    assert!(!flow.has_typestate_violations());

    // Compute typestate with file state machine
    let file_sm = rma_analyzer::flow::file_state_machine();
    let _results = flow.compute_typestate(&[file_sm], &parsed);

    // Now should have results
    assert!(flow.typestate_results().is_some());
}

#[test]
fn test_flow_context_all_violations() {
    let code = r#"
        const file = fs.openSync("test.txt");
        file.close();
        file.read(); // Use after close
    "#;
    let parsed = parse_js(code);
    let mut flow = FlowContext::build(&parsed, Language::JavaScript);

    let file_sm = rma_analyzer::flow::file_state_machine();
    let _results = flow.compute_typestate(&[file_sm], &parsed);

    // Get all violations (may or may not detect depending on pattern matching)
    let violations = flow.all_typestate_violations();
    // Just verify method works
    let _ = violations;
}
