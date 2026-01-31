//! Config command implementation

use crate::ui::theme::Theme;
use crate::ConfigAction;
use anyhow::Result;
use colored::Colorize;
use rma_common::{RmaTomlConfig, WarningLevel};

pub fn run(action: ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Get { key } => get_config(&key),
        ConfigAction::Set { key, value } => set_config(&key, &value),
        ConfigAction::List => list_config(),
        ConfigAction::Edit => edit_config(),
        ConfigAction::Path => show_config_path(),
        ConfigAction::Reset { force } => reset_config(force),
        ConfigAction::Validate => validate_config(),
    }
}

fn validate_config() -> Result<()> {
    println!();
    println!("{}", Theme::header("Validating Configuration"));
    println!("{}", Theme::separator(60));
    println!();

    // Try to find config
    let cwd = std::env::current_dir()?;
    let (config_path, config) = match RmaTomlConfig::discover(&cwd) {
        Some((path, cfg)) => (path, cfg),
        None => {
            println!(
                "{} No configuration file found",
                Theme::warning_mark()
            );
            println!();
            println!("  Looking for:");
            println!("    {} rma.toml", Theme::bullet());
            println!("    {} .rma/rma.toml", Theme::bullet());
            println!("    {} .rma.toml", Theme::bullet());
            println!();
            println!(
                "  Run {} to create one",
                "rma init".yellow()
            );
            return Ok(());
        }
    };

    println!(
        "  {} Config file: {}",
        Theme::info_mark(),
        config_path.display().to_string().cyan()
    );
    println!();

    // Validate
    let warnings = config.validate();

    if warnings.is_empty() {
        println!(
            "{} Configuration is valid!",
            Theme::success_mark()
        );
        println!();

        // Show summary
        println!("  {}", "Summary:".cyan().bold());
        println!(
            "    {} Default profile: {}",
            Theme::bullet(),
            config.profiles.default.to_string().yellow()
        );
        println!(
            "    {} Rules enabled: {}",
            Theme::bullet(),
            config.rules.enable.join(", ").green()
        );
        if !config.rules.disable.is_empty() {
            println!(
                "    {} Rules disabled: {}",
                Theme::bullet(),
                config.rules.disable.join(", ").red()
            );
        }
        if !config.severity.is_empty() {
            println!(
                "    {} Severity overrides: {}",
                Theme::bullet(),
                config.severity.len().to_string().cyan()
            );
        }
        if !config.threshold_overrides.is_empty() {
            println!(
                "    {} Threshold overrides: {}",
                Theme::bullet(),
                config.threshold_overrides.len().to_string().cyan()
            );
        }
        println!(
            "    {} Baseline mode: {:?}",
            Theme::bullet(),
            config.baseline.mode
        );
    } else {
        let errors: Vec<_> = warnings.iter().filter(|w| w.level == WarningLevel::Error).collect();
        let warns: Vec<_> = warnings.iter().filter(|w| w.level == WarningLevel::Warning).collect();

        if !errors.is_empty() {
            println!("{} Configuration has errors:", Theme::error_mark());
            println!();
            for error in &errors {
                println!("    {} {}", "✗".red(), error.message);
            }
        }

        if !warns.is_empty() {
            println!();
            println!("{} Warnings:", Theme::warning_mark());
            println!();
            for warn in &warns {
                println!("    {} {}", "⚠".yellow(), warn.message);
            }
        }

        if !errors.is_empty() {
            std::process::exit(1);
        }
    }

    println!();

    Ok(())
}

fn get_config(key: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;

    let config = match RmaTomlConfig::discover(&cwd) {
        Some((_, cfg)) => cfg,
        None => {
            eprintln!("{} No configuration found", Theme::error_mark());
            std::process::exit(1);
        }
    };

    let json = serde_json::to_value(&config)?;
    let value = get_nested_value(&json, key);

    match value {
        Some(v) => println!("{}", serde_json::to_string_pretty(&v)?),
        None => {
            eprintln!("{} Key not found: {}", Theme::error_mark(), key.yellow());
            std::process::exit(1);
        }
    }

    Ok(())
}

fn set_config(key: &str, value: &str) -> Result<()> {
    let cwd = std::env::current_dir()?;

    let (config_path, mut config) = RmaTomlConfig::discover(&cwd)
        .ok_or_else(|| anyhow::anyhow!("No configuration found. Run 'rma init' first."))?;

    let mut json = serde_json::to_value(&config)?;

    // Parse the value
    let parsed_value: serde_json::Value = serde_json::from_str(value)
        .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));

    set_nested_value(&mut json, key, parsed_value)?;

    // Convert back to config
    config = serde_json::from_value(json)?;

    // Save as TOML
    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&config_path, toml_str)?;

    println!(
        "{} Configuration updated: {} = {}",
        Theme::success_mark(),
        key.cyan(),
        value.bright_white()
    );

    Ok(())
}

fn list_config() -> Result<()> {
    let cwd = std::env::current_dir()?;

    let (config_path, config) = match RmaTomlConfig::discover(&cwd) {
        Some((path, cfg)) => (path, cfg),
        None => {
            println!("{} No configuration found", Theme::warning_mark());
            println!("  Run {} to create one", "rma init".yellow());
            return Ok(());
        }
    };

    println!();
    println!("{}", Theme::header("Configuration"));
    println!("{}", Theme::separator(60));
    println!();

    let json = serde_json::to_value(&config)?;
    print_config_tree(&json, "");

    println!();
    println!(
        "  {} {}",
        "Config file:".dimmed(),
        config_path.display()
    );
    println!();

    Ok(())
}

fn print_config_tree(value: &serde_json::Value, prefix: &str) {
    if let serde_json::Value::Object(map) = value {
        for (key, val) in map {
            let new_prefix = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{}.{}", prefix, key)
            };

            match val {
                serde_json::Value::Object(_) => {
                    println!("  {}", new_prefix.cyan());
                    print_config_tree(val, &new_prefix);
                }
                _ => {
                    let formatted_val = match val {
                        serde_json::Value::String(s) => format!("\"{}\"", s).green(),
                        serde_json::Value::Bool(b) => b.to_string().yellow(),
                        serde_json::Value::Number(n) => n.to_string().bright_blue(),
                        serde_json::Value::Array(arr) => format!("[{} items]", arr.len()).dimmed(),
                        _ => val.to_string().dimmed(),
                    };
                    println!("    {}: {}", key.bright_white(), formatted_val);
                }
            }
        }
    }
}

fn edit_config() -> Result<()> {
    let cwd = std::env::current_dir()?;

    let config_path = match RmaTomlConfig::discover(&cwd) {
        Some((path, _)) => path,
        None => {
            // Create default config
            let default_path = cwd.join("rma.toml");
            let default_config = RmaTomlConfig::default_toml(rma_common::Profile::Balanced);
            std::fs::write(&default_path, default_config)?;
            default_path
        }
    };

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

    println!(
        "{} Opening {} in {}...",
        Theme::info_mark(),
        config_path.display(),
        editor.cyan()
    );

    std::process::Command::new(&editor)
        .arg(&config_path)
        .status()?;

    // Validate after editing
    println!();
    if let Ok(content) = std::fs::read_to_string(&config_path) {
        match toml::from_str::<RmaTomlConfig>(&content) {
            Ok(config) => {
                let warnings = config.validate();
                if warnings.is_empty() {
                    println!("{} Configuration saved and valid", Theme::success_mark());
                } else {
                    println!("{} Configuration saved with warnings:", Theme::warning_mark());
                    for w in &warnings {
                        println!("  {} {}", Theme::bullet(), w.message.yellow());
                    }
                }
            }
            Err(e) => {
                println!("{} Configuration has syntax errors:", Theme::error_mark());
                println!("  {}", e.to_string().red());
            }
        }
    }

    Ok(())
}

fn show_config_path() -> Result<()> {
    let cwd = std::env::current_dir()?;

    match RmaTomlConfig::discover(&cwd) {
        Some((path, _)) => println!("{}", path.display()),
        None => {
            // Show where config would be created
            let default_path = cwd.join("rma.toml");
            println!("{} (not found)", default_path.display());
        }
    }

    Ok(())
}

fn reset_config(force: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let config_path = cwd.join("rma.toml");

    if !force {
        println!(
            "{} This will reset all configuration to defaults.",
            Theme::warning_mark()
        );
        print!("Continue? [y/N] ");
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let default_config = RmaTomlConfig::default_toml(rma_common::Profile::Balanced);
    std::fs::write(&config_path, default_config)?;

    println!("{} Configuration reset to defaults", Theme::success_mark());
    println!("  Saved to: {}", config_path.display().to_string().cyan());

    Ok(())
}

fn get_nested_value<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    let parts: Vec<&str> = key.split('.').collect();
    let mut current = value;

    for part in parts {
        current = current.get(part)?;
    }

    Some(current)
}

fn set_nested_value(
    value: &mut serde_json::Value,
    key: &str,
    new_value: serde_json::Value,
) -> Result<()> {
    let parts: Vec<&str> = key.split('.').collect();

    if parts.is_empty() {
        anyhow::bail!("Empty key");
    }

    let mut current = value;

    for part in &parts[..parts.len() - 1] {
        current = current
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("Invalid path"))?
            .entry(*part)
            .or_insert(serde_json::json!({}));
    }

    if let Some(obj) = current.as_object_mut() {
        obj.insert(parts[parts.len() - 1].to_string(), new_value);
    }

    Ok(())
}
