//! Doctor command - checks RMA installation health

use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
#[cfg(feature = "oxc")]
use rma_analyzer::providers::OxcNativeProvider;
use rma_analyzer::providers::{
    AnalysisProvider, GosecProvider, OsvProvider, OxlintProvider, PmdProvider, RustSecProvider,
};
use rma_common::{GosecProviderConfig, Language, OsvProviderConfig, PmdProviderConfig, RmaConfig};
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
            // Fallback for other languages
            _ => "txt",
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
        "  {} Rules available for all 6 languages",
        Theme::success_mark()
    );
    if args.verbose {
        println!("    Rust (High-confidence):");
        println!("      • rust/unsafe-block, rust/transmute-used");
        println!("      • rust/command-injection, rust/raw-pointer-deref");
        println!("    Rust (Review hints):");
        println!("      • rust/sql-injection-hint, rust/path-traversal-hint");
        println!("      • rust/unwrap-hint, rust/panic-hint");
        println!("    JavaScript/TypeScript:");
        println!("      • js/dynamic-code-execution, js/timer-string-eval");
        println!("      • js/innerhtml-xss, js/console-log");
        println!("    Python:");
        println!("      • python/dynamic-execution, python/shell-injection");
        println!("      • python/hardcoded-secret");
        println!("    Go:");
        println!("      • go/command-injection, go/sql-injection");
        println!("      • go/unsafe-pointer, go/insecure-http");
        println!("      • go/ignored-error-hint");
        println!("    Java:");
        println!("      • java/command-execution, java/sql-injection");
        println!("      • java/insecure-deserialization, java/xxe-vulnerability");
        println!("      • java/path-traversal, java/generic-exception-hint");
        println!("    Generic (all languages):");
        println!("      • generic/hardcoded-secret, generic/insecure-crypto");
        println!("      • generic/todo-fixme, generic/long-function");
    }

    // 5. Analysis Providers
    print_section("Analysis Providers");
    check_providers(args.verbose);

    // 6. Plugin system
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

    // 7. Quick scan test
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

fn check_providers(verbose: bool) {
    // RMA native - always available
    println!(
        "  {} {} (built-in, always available)",
        Theme::success_mark(),
        "rma".green()
    );

    // Oxc native - native Rust linter using oxc_linter
    #[cfg(feature = "oxc")]
    {
        let oxc = OxcNativeProvider::new();
        if oxc.is_available() {
            let version = oxc.version().unwrap_or_else(|| "unknown".to_string());
            println!(
                "  {} {} v{} (native JS/TS linting, 520+ rules)",
                Theme::success_mark(),
                "oxc".green(),
                version
            );
        } else {
            println!(
                "  {} {} (not available)",
                Theme::info_mark(),
                "oxc".dimmed()
            );
        }
    }
    #[cfg(not(feature = "oxc"))]
    {
        println!(
            "  {} {} (not compiled - oxc feature disabled)",
            Theme::info_mark(),
            "oxc".dimmed()
        );
    }

    // RustSec - Rust crates, always available
    let rustsec = RustSecProvider::new();
    if rustsec.is_available() {
        let version = rustsec.version().unwrap_or_else(|| "unknown".to_string());
        println!(
            "  {} {} v{} (Rust dependency vulnerabilities)",
            Theme::success_mark(),
            "rustsec".green(),
            version
        );
    } else {
        println!(
            "  {} {} (database unavailable)",
            Theme::info_mark(),
            "rustsec".dimmed()
        );
    }

    // Oxlint - external binary
    let oxlint = OxlintProvider::new();
    if oxlint.is_available() {
        let version = oxlint.version().unwrap_or_else(|| "unknown".to_string());
        println!(
            "  {} {} v{} (external binary)",
            Theme::success_mark(),
            "oxlint".green(),
            version
        );
    } else {
        println!(
            "  {} {} (not installed - npm i -g oxlint)",
            Theme::info_mark(),
            "oxlint".dimmed()
        );
    }

    // PMD - external binary
    let pmd = PmdProvider::new(PmdProviderConfig::default());
    if pmd.is_available() {
        let version = pmd.version().unwrap_or_else(|| "unknown".to_string());
        println!(
            "  {} {} v{} (Java analysis)",
            Theme::success_mark(),
            "pmd".green(),
            version
        );
    } else {
        println!(
            "  {} {} (not installed)",
            Theme::info_mark(),
            "pmd".dimmed()
        );
    }

    // Gosec - external binary
    let gosec = GosecProvider::new(GosecProviderConfig::default());
    if gosec.is_available() {
        let version = gosec.version().unwrap_or_else(|| "unknown".to_string());
        println!(
            "  {} {} v{} (Go security analysis)",
            Theme::success_mark(),
            "gosec".green(),
            version
        );
    } else {
        println!(
            "  {} {} (not installed - go install github.com/securego/gosec/v2/cmd/gosec@latest)",
            Theme::info_mark(),
            "gosec".dimmed()
        );
    }

    // OSV - multi-language dependency vulnerability scanning
    let osv_config = OsvProviderConfig::default();
    let osv = OsvProvider::new(osv_config.clone());
    if osv.is_available() {
        let version = osv.version().unwrap_or_else(|| "unknown".to_string());
        println!(
            "  {} {} v{} (multi-language dep vulnerabilities)",
            Theme::success_mark(),
            "osv".green(),
            version
        );
        if verbose {
            // Show cache status
            let cache_dir = super::cache::get_osv_cache_dir();
            let cache_stats = super::cache::CacheStats::gather(&cache_dir);

            println!("    Ecosystems: crates.io, npm, PyPI, Go, Maven");
            println!(
                "    Lockfiles: Cargo.lock, package-lock.json, go.mod, requirements.txt, pom.xml"
            );
            println!(
                "    Cache: {} ({} entries, {})",
                if cache_stats.exists {
                    "present"
                } else {
                    "not initialized"
                },
                cache_stats.entry_count,
                cache_stats.format_size()
            );
            println!("    Cache path: {}", cache_dir.display());
            println!("    Offline support: yes (use --osv-offline)");
        }
    } else {
        println!(
            "  {} {} (offline mode or network unavailable)",
            Theme::info_mark(),
            "osv".dimmed()
        );
    }
}
