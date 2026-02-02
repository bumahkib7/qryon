# RMA - Rust Monorepo Analyzer

Ultra-fast Rust-native code intelligence and security analysis platform for large enterprise monorepos.

## Installation

```bash
npm install -g rma-cli
```

## Usage

```bash
# Scan current directory
rma scan .

# Scan with AI-powered analysis
rma scan ./src --ai

# Watch mode for continuous analysis
rma watch .

# Generate SARIF output for CI/CD
rma scan . --output sarif -f results.sarif
```

## Alternative Installation

If npm installation fails, try:

```bash
# Cargo (requires Rust)
cargo install rma-cli

# Shell script (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/anthropics/rma/master/install.sh | bash

# Homebrew (macOS/Linux)
brew install anthropics/tap/rma
```

## Documentation

Full documentation: https://github.com/anthropics/rma

## License

MIT OR Apache-2.0
