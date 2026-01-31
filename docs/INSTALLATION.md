# Installation Guide

This guide covers all installation methods for RMA (Rust Monorepo Analyzer).

## Quick Install (Recommended)

### Linux / macOS

Run this single command in your terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.sh | bash
```

This will:
1. Detect your OS and architecture
2. Download the appropriate pre-built binary
3. Install to `~/.local/bin`
4. Add to your PATH (updates shell config)
5. Verify the installation

### Windows

Run in PowerShell (as Administrator recommended):

```powershell
iwr -useb https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.ps1 | iex
```

This will:
1. Download the Windows binary
2. Install to `%USERPROFILE%\.local\bin`
3. Add to your PATH
4. Verify the installation

## Alternative Methods

### Cargo (from crates.io)

If you have Rust installed:

```bash
cargo install rma-cli
```

### Cargo (from GitHub)

```bash
cargo install --git https://github.com/bumahkib7/rust-monorepo-analyzer rma-cli
```

### Docker

```bash
# Pull the image
docker pull ghcr.io/bumahkib7/rust-monorepo-analyzer:latest

# Run a scan
docker run -v $(pwd):/workspace ghcr.io/bumahkib7/rust-monorepo-analyzer scan /workspace

# Run with options
docker run -v $(pwd):/workspace ghcr.io/bumahkib7/rust-monorepo-analyzer scan /workspace --output json
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/bumahkib7/rust-monorepo-analyzer.git
cd rust-monorepo-analyzer

# Build release binary
cargo build --release -p rma-cli

# Binary is at: target/release/rma

# Or install directly
cargo install --path crates/cli
```

### Makefile

```bash
git clone https://github.com/bumahkib7/rust-monorepo-analyzer.git
cd rust-monorepo-analyzer
make install
```

## Platform Support

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | x86_64 (glibc) | rma-x86_64-unknown-linux-gnu |
| Linux | x86_64 (musl) | rma-x86_64-unknown-linux-musl |
| Linux | ARM64 | rma-aarch64-unknown-linux-gnu |
| macOS | Intel | rma-x86_64-apple-darwin |
| macOS | Apple Silicon | rma-aarch64-apple-darwin |
| Windows | x86_64 | rma-x86_64-pc-windows-msvc |

## Custom Install Location

### Linux/macOS

Set the `RMA_INSTALL_DIR` environment variable before running the install script:

```bash
RMA_INSTALL_DIR=/opt/bin curl -fsSL https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.sh | bash
```

### Windows

Edit the `$installDir` variable in the PowerShell script.

## Verifying Installation

```bash
rma --version
```

Expected output:
```
rma-cli 0.1.0
```

## Shell Completions

After installation, generate shell completions:

```bash
# Bash
rma completions bash > ~/.local/share/bash-completion/completions/rma

# Zsh (add to ~/.zshrc: fpath=(~/.zfunc $fpath))
mkdir -p ~/.zfunc
rma completions zsh > ~/.zfunc/_rma

# Fish
rma completions fish > ~/.config/fish/completions/rma.fish

# PowerShell (add to profile)
rma completions powershell >> $PROFILE
```

## Updating

### Script Install

Re-run the install script - it will overwrite the existing binary:

```bash
curl -fsSL https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.sh | bash
```

### Cargo

```bash
cargo install rma-cli --force
```

### Docker

```bash
docker pull ghcr.io/bumahkib7/rust-monorepo-analyzer:latest
```

## Uninstalling

### Linux/macOS

```bash
rm ~/.local/bin/rma
# Optionally remove config
rm -rf ~/.config/rma
```

### Windows

```powershell
Remove-Item "$env:USERPROFILE\.local\bin\rma.exe"
# Optionally remove config
Remove-Item -Recurse "$env:USERPROFILE\.config\rma"
```

### Cargo

```bash
cargo uninstall rma-cli
```

## Troubleshooting

### "command not found"

Ensure `~/.local/bin` is in your PATH:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$PATH:$HOME/.local/bin"
```

Then restart your terminal or run `source ~/.bashrc`.

### Permission Denied

Make the binary executable:

```bash
chmod +x ~/.local/bin/rma
```

### SSL/TLS Errors on Linux

If using the musl binary and encountering SSL errors, try the glibc binary or install from source.

### macOS Security Warning

If macOS blocks the binary:

```bash
xattr -d com.apple.quarantine ~/.local/bin/rma
```

Or go to System Preferences > Security & Privacy and click "Allow Anyway".
