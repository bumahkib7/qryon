//! Doctor command - checks RMA installation health

use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
use rma_common::{Language, RmaConfig};
use rma_parser::ParserEngine;
use std::path::Path;

pub struct DoctorArgs {
    pub verbose: bool,
}

pub fn run(args: DoctorArgs) -> Result<()> {
    println!();
    println!("{}", "🩺 RMA Doctor".cyan().bold());
    println!("{}", Theme::separator(60));
    println!();

    let mut all_ok = true;

    // 1. Version info
    print_section("Version");
    println!(
        "  {} rma {}",
        Theme::success_mark(),
        env!("CARGO_PKG_VERSION").bright_white()
    );

    // 2. Configuration
    print_section("Configuration");
    match check_config() {
        Ok(msg) => println!("  {} {}", Theme::success_mark(), msg),
        Err(msg) => {
            println!("  {} {}", Theme::warning_mark(), msg.yellow());
        }
    }

    // 3. Language parsers
    print_section("Language Parsers");
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config);

    let languages = [
        (Language::Rust, "Rust", "fn main() {}"),
        (Language::JavaScript, "JavaScript", "function f() {}"),
        (Language::TypeScript, "TypeScript", "function f(): void {}"),
        (Language::Python, "Python", "def f(): pass"),
        (Language::Go, "Go", "package main"),
        (Language::Java, "Java", "class C {}"),
    ];

    for (lang, name, sample) in languages {
        let ext = match lang {
            Language::Rust => "rs",
            Language::JavaScript => "js",
            Language::TypeScript => "ts",
            Language::Python => "py",
            Language::Go => "go",
            Language::Java => "java",
            Language::Unknown => "txt",
        };

        let test_path = format!("test.{}", ext);
        match parser.parse_file(Path::new(&test_path), sample) {
            Ok(parsed) => {
                if parsed.tree.root_node().has_error() {
                    println!(
                        "  {} {} (parse errors)",
                        Theme::warning_mark(),
                        name.yellow()
                    );
                } else {
                    let detail = if args.verbose {
                        format!(" (nodes: {})", parsed.tree.root_node().descendant_count())
                    } else {
                        String::new()
                    };
                    println!("  {} {}{}", Theme::success_mark(), name.green(), detail);
                }
            }
            Err(e) => {
                println!("  {} {} - {}", Theme::error_mark(), name.red(), e);
                all_ok = false;
            }
        }
    }

    // 4. Security rules
    print_section("Security Rules");
    println!(
        "  {} Rules available",
        Theme::success_mark()
    );
    if args.verbose {
        println!("    High-confidence sinks:");
        println!("      • rust/unsafe-block, rust/transmute-used");
        println!("      • rust/command-injection, rust/raw-pointer-deref");
        println!("      • js/eval, js/innerHTML, js/setTimeout-string");
        println!("      • py/eval, py/exec, py/subprocess-shell");
        println!("    Review hints (low confidence):");
        println!("      • rust/sql-injection-hint, rust/path-traversal-hint");
        println!("      • rust/unwrap-hint, rust/panic-hint");
    }

    // 5. Plugin system
    print_section("Plugin System");
    match check_plugins() {
        Ok((loaded, total)) => {
            if total > 0 {
                println!(
                    "  {} {}/{} plugins available",
                    Theme::success_mark(),
                    loaded,
                    total
                );
            } else {
                println!("  {} No plugins installed", Theme::info_mark());
            }
        }
        Err(e) => {
            println!("  {} Plugin check failed: {}", Theme::warning_mark(), e);
        }
    }

    // 6. Quick scan test
    print_section("Scan Test");
    match quick_scan_test() {
        Ok(duration_ms) => {
            println!(
                "  {} Basic scan works ({}ms)",
                Theme::success_mark(),
                duration_ms
            );
        }
        Err(e) => {
            println!("  {} Scan test failed: {}", Theme::error_mark(), e);
            all_ok = false;
        }
    }

    // Summary
    println!();
    println!("{}", Theme::separator(60));
    if all_ok {
        println!(
            "{}",
            "✅ All checks passed! RMA is ready to use.".green().bold()
        );
    } else {
        println!(
            "{}",
            "⚠️  Some checks failed. See above for details."
                .yellow()
                .bold()
        );
    }
    println!();

    Ok(())
}

fn print_section(name: &str) {
    println!("  {}", name.bright_white().bold());
}

fn check_config() -> Result<String, String> {
    // Check for .rma.toml in current directory
    if Path::new(".rma.toml").exists() {
        match rma_common::RmaTomlConfig::load(Path::new(".rma.toml")) {
            Ok(_) => Ok("Found .rma.toml (valid)".to_string()),
            Err(e) => Err(format!(".rma.toml exists but invalid: {}", e)),
        }
    } else {
        Ok("Using default configuration (no .rma.toml)".to_string())
    }
}

fn check_plugins() -> Result<(usize, usize), String> {
    // Check ~/.rma/plugins directory
    let plugin_dir = dirs::home_dir()
        .map(|h| h.join(".rma").join("plugins"))
        .ok_or_else(|| "Could not determine home directory".to_string())?;

    if !plugin_dir.exists() {
        return Ok((0, 0));
    }

    let count = std::fs::read_dir(&plugin_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "wasm" || ext == "so" || ext == "dylib")
        })
        .count();

    Ok((count, count))
}

fn quick_scan_test() -> Result<u128, String> {
    use std::time::Instant;

    let start = Instant::now();

    // Create a minimal test
    let config = RmaConfig::default();
    let parser = ParserEngine::new(config.clone());
    let analyzer = rma_analyzer::AnalyzerEngine::new(config);

    let test_code = r#"fn main() { println!("test"); }"#;
    let parsed = parser
        .parse_file(Path::new("test.rs"), test_code)
        .map_err(|e| e.to_string())?;

    let _findings = analyzer.analyze_file(&parsed);

    Ok(start.elapsed().as_millis())
}
