# Installation Guide

This guide covers all installation methods for Qryon.

## Quick Install (Recommended)

### Linux / macOS

Run this single command in your terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/bumahkib7/qryon/master/install.sh | bash
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
iwr -useb https://raw.githubusercontent.com/bumahkib7/qryon/master/install.ps1 | iex
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
cargo install --git https://github.com/bumahkib7/qryon rma-cli
```

### Docker

```bash
# Pull the image
docker pull ghcr.io/bumahkib7/qryon:latest

# Run a scan
docker run -v $(pwd):/workspace ghcr.io/bumahkib7/qryon scan /workspace

# Run with options
docker run -v $(pwd):/workspace ghcr.io/bumahkib7/qryon scan /workspace --output json
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/bumahkib7/qryon.git
cd qryon

# Build release binary
cargo build --release -p rma-cli

# Binary is at: target/release/qryon

# Or install directly
cargo install --path crates/cli
```

### Makefile

```bash
git clone https://github.com/bumahkib7/qryon.git
cd qryon
make install
```

## Platform Support

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | x86_64 (glibc) | qryon-x86_64-unknown-linux-gnu |
| Linux | x86_64 (musl) | qryon-x86_64-unknown-linux-musl |
| Linux | ARM64 | qryon-aarch64-unknown-linux-gnu |
| macOS | Intel | qryon-x86_64-apple-darwin |
| macOS | Apple Silicon | qryon-aarch64-apple-darwin |
| Windows | x86_64 | qryon-x86_64-pc-windows-msvc |

## Custom Install Location

### Linux/macOS

Set the `QRYON_INSTALL_DIR` environment variable before running the install script:

```bash
QRYON_INSTALL_DIR=/opt/bin curl -fsSL https://raw.githubusercontent.com/bumahkib7/qryon/master/install.sh | bash
```

### Windows

Edit the `$installDir` variable in the PowerShell script.

## Verifying Installation

```bash
qryon --version
```

Expected output:
```
rma-cli 0.1.0
```

## Shell Completions

After installation, generate shell completions:

```bash
# Bash
qryon completions bash > ~/.local/share/bash-completion/completions/qryon

# Zsh (add to ~/.zshrc: fpath=(~/.zfunc $fpath))
mkdir -p ~/.zfunc
qryon completions zsh > ~/.zfunc/_qryon

# Fish
qryon completions fish > ~/.config/fish/completions/qryon.fish

# PowerShell (add to profile)
qryon completions powershell >> $PROFILE
```

## Updating

### Script Install

Re-run the install script - it will overwrite the existing binary:

```bash
curl -fsSL https://raw.githubusercontent.com/bumahkib7/qryon/master/install.sh | bash
```

### Cargo

```bash
cargo install rma-cli --force
```

### Docker

```bash
docker pull ghcr.io/bumahkib7/qryon:latest
```

## Uninstalling

### Linux/macOS

```bash
rm ~/.local/bin/qryon
# Optionally remove config
rm -rf ~/.config/qryon
```

### Windows

```powershell
Remove-Item "$env:USERPROFILE\.local\bin\qryon.exe"
# Optionally remove config
Remove-Item -Recurse "$env:USERPROFILE\.config\qryon"
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
chmod +x ~/.local/bin/qryon
```

### SSL/TLS Errors on Linux

If using the musl binary and encountering SSL errors, try the glibc binary or install from source.

### macOS Security Warning

If macOS blocks the binary:

```bash
xattr -d com.apple.quarantine ~/.local/bin/qryon
```

Or go to System Preferences > Security & Privacy and click "Allow Anyway".
