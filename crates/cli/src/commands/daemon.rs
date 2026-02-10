//! Daemon command implementation

use crate::ui::theme::Theme;
use anyhow::Result;
use colored::Colorize;

pub struct DaemonArgs {
    pub port: u16,
    pub host: String,
    pub background: bool,
}

pub fn run(args: DaemonArgs) -> Result<()> {
    println!();
    println!("{}", "🚀 Qryon Daemon".cyan().bold());
    println!("{}", Theme::separator(50));
    println!(
        "  {} {}:{}",
        "Binding to:".dimmed(),
        args.host.bright_white(),
        args.port.to_string().bright_white()
    );

    if args.background {
        println!("  {} {}", "Mode:".dimmed(), "background".yellow());
    }

    println!();
    println!("{}", "📡 Endpoints:".cyan());
    println!(
        "  {} http://{}:{}/health",
        "Health:".dimmed(),
        args.host,
        args.port
    );
    println!(
        "  {} http://{}:{}/api/v1/",
        "REST API:".dimmed(),
        args.host,
        args.port
    );
    println!(
        "  {} ws://{}:{}/ws/watch",
        "WebSocket:".dimmed(),
        args.host,
        args.port
    );
    println!();
    println!("{}", "🌐 Web Dashboard:".cyan());
    println!(
        "  {} {}",
        "Open:".dimmed(),
        "editors/web-dashboard/index.html".bright_white()
    );
    println!(
        "  {} file://{}/editors/web-dashboard/index.html",
        "Or:".dimmed(),
        std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".to_string())
    );
    println!();

    // Use tokio runtime to start the daemon
    let rt = tokio::runtime::Runtime::new()?;

    rt.block_on(async {
        println!("{} Starting server...", Theme::info_mark());

        let addr = format!("{}:{}", args.host, args.port);

        // Start the daemon server
        match rma_daemon::start_server(&addr).await {
            Ok(_) => {
                println!("{} Server stopped", Theme::info_mark());
            }
            Err(e) => {
                eprintln!("{} Failed to start server: {}", Theme::error_mark(), e);
                return Err(anyhow::anyhow!("Server failed: {}", e));
            }
        }

        Ok(())
    })
}
