//! Init command implementation

use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;
use rma_common::{Profile, RmaTomlConfig};
use std::path::PathBuf;

pub struct InitArgs {
    pub path: PathBuf,
    pub force: bool,
    pub with_ai: bool,
    pub profile: Option<Profile>,
}

pub fn run(args: InitArgs) -> Result<()> {
    let config_dir = args.path.join(".qryon");
    let config_file = args.path.join("qryon.toml");
    let legacy_config = config_dir.join("config.json");

    // Check if already initialized
    if (config_file.exists() || legacy_config.exists()) && !args.force {
        println!(
            "{} Qryon is already initialized in this directory",
            Theme::warning_mark()
        );
        if config_file.exists() {
            println!(
                "  Config file: {}",
                config_file.display().to_string().cyan()
            );
        }
        println!("  Use {} to reinitialize", "--force".yellow());
        return Ok(());
    }

    let profile = args.profile.unwrap_or(Profile::Balanced);

    println!();
    println!("{}", "🚀 Initializing Qryon".cyan().bold());
    println!("{}", Theme::separator(50));

    // Create directory structure
    std::fs::create_dir_all(&config_dir)?;
    std::fs::create_dir_all(config_dir.join("index"))?;
    std::fs::create_dir_all(config_dir.join("cache"))?;

    println!(
        "  {} Created {}",
        Theme::success_mark(),
        ".qryon/".bright_white()
    );

    // Generate TOML config
    let toml_content = RmaTomlConfig::default_toml(profile);

    // Optionally add AI configuration
    let final_content = if args.with_ai {
        format!(
            r#"{}
[ai]
# AI-powered analysis settings
enabled = true
provider = "claude"
# api_key = "${{ANTHROPIC_API_KEY}}"  # Use environment variable
"#,
            toml_content
        )
    } else {
        toml_content
    };

    std::fs::write(&config_file, &final_content)?;

    println!(
        "  {} Created {} (profile: {})",
        Theme::success_mark(),
        "qryon.toml".bright_white(),
        profile.to_string().cyan()
    );

    if args.with_ai {
        println!("  {} AI features enabled", Theme::success_mark());
    }

    // Create .gitignore for RMA directory
    let gitignore_path = config_dir.join(".gitignore");
    let gitignore_content = r#"# Qryon cache and index (do not commit)
index/
cache/
*.lock

# Baseline can be committed to track legacy issues
# !baseline.json
"#;
    std::fs::write(&gitignore_path, gitignore_content)?;
    println!(
        "  {} Created {}",
        Theme::success_mark(),
        ".qryon/.gitignore".bright_white()
    );

    println!();
    println!("{}", Theme::double_separator(50));
    println!("{} Qryon initialized successfully!", Theme::success_mark());
    println!();
    println!("  {}", "Configuration:".cyan().bold());
    println!("  {} Config file: {}", Theme::bullet(), "qryon.toml".yellow());
    println!(
        "  {} Profile: {} ({})",
        Theme::bullet(),
        profile.to_string().yellow(),
        match profile {
            Profile::Fast => "relaxed thresholds",
            Profile::Balanced => "recommended defaults",
            Profile::Strict => "high-quality standards",
        }
    );
    println!();
    println!("  {}", "Next steps:".cyan().bold());
    println!(
        "  {} Run {} to analyze your code",
        Theme::bullet(),
        "qryon scan".yellow()
    );
    println!(
        "  {} Run {} to validate configuration",
        Theme::bullet(),
        "qryon config validate".yellow()
    );
    println!(
        "  {} Run {} to create a baseline for legacy issues",
        Theme::bullet(),
        "qryon baseline".yellow()
    );
    println!(
        "  {} Edit {} to customize rules and thresholds",
        Theme::bullet(),
        "qryon.toml".yellow()
    );
    println!();

    Ok(())
}
