//! Example: Load Semgrep rules and show statistics

use rma_rules::{load_rules_from_dir, RuleRegistry};
use std::path::Path;

fn main() {
    let semgrep_dir = Path::new("external/semgrep-rules");

    if !semgrep_dir.exists() {
        eprintln!("Semgrep rules not found at {}", semgrep_dir.display());
        eprintln!("Run: git clone --depth 1 https://github.com/semgrep/semgrep-rules.git external/semgrep-rules");
        return;
    }

    println!("Loading rules from {}...", semgrep_dir.display());

    let mut registry = RuleRegistry::new();

    // Load Python rules
    let python_dir = semgrep_dir.join("python");
    if python_dir.exists() {
        match load_rules_from_dir(&python_dir) {
            Ok(rules) => {
                println!("  Python: {} rules", rules.len());
                registry.add_rules(rules);
            }
            Err(e) => eprintln!("  Python: Error - {}", e),
        }
    }

    // Load JavaScript rules
    let js_dir = semgrep_dir.join("javascript");
    if js_dir.exists() {
        match load_rules_from_dir(&js_dir) {
            Ok(rules) => {
                println!("  JavaScript: {} rules", rules.len());
                registry.add_rules(rules);
            }
            Err(e) => eprintln!("  JavaScript: Error - {}", e),
        }
    }

    // Load Java rules
    let java_dir = semgrep_dir.join("java");
    if java_dir.exists() {
        match load_rules_from_dir(&java_dir) {
            Ok(rules) => {
                println!("  Java: {} rules", rules.len());
                registry.add_rules(rules);
            }
            Err(e) => eprintln!("  Java: Error - {}", e),
        }
    }

    // Load Go rules
    let go_dir = semgrep_dir.join("go");
    if go_dir.exists() {
        match load_rules_from_dir(&go_dir) {
            Ok(rules) => {
                println!("  Go: {} rules", rules.len());
                registry.add_rules(rules);
            }
            Err(e) => eprintln!("  Go: Error - {}", e),
        }
    }

    let stats = registry.stats();
    println!(
        "\nTotal: {} rules across {} languages",
        stats.total_rules, stats.languages
    );

    println!("\nRules per language:");
    let mut langs: Vec<_> = stats.rules_per_language.iter().collect();
    langs.sort_by(|a, b| b.1.cmp(a.1));
    for (lang, count) in langs.iter().take(10) {
        println!("  {}: {}", lang, count);
    }
}
