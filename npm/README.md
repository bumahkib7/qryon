# Qryon

Ultra-fast Rust-native code intelligence and security analysis platform for large enterprise monorepos.

## Installation

```bash
npm install -g rma-cli
```

## Usage

```bash
# Scan current directory
qryon scan .

# Scan with AI-powered analysis
qryon scan ./src --ai

# Watch mode for continuous analysis
qryon watch .

# Generate SARIF output for CI/CD
qryon scan . --output sarif -f results.sarif
```

## Alternative Installation

If npm installation fails, try:

```bash
# Cargo (requires Rust)
cargo install rma-cli

# Shell script (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/bumahkib7/qryon/master/install.sh | bash

# Homebrew (macOS/Linux)
brew install bumahkib7/tap/qryon
```

## Documentation

Full documentation: https://github.com/bumahkib7/qryon

## License

MIT OR Apache-2.0
