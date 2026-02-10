# Qryon

Ultra-fast Rust-native code intelligence and security analysis platform for large enterprise monorepos.

## Installation

```bash
npm install -g qryon
```

## Usage

```bash
# Scan current directory
qryon scan .

# AI-powered finding triage (triages static findings with AI)
export ANTHROPIC_API_KEY=sk-ant-...
qryon scan . --ai

# Use OpenAI or local Ollama instead
qryon scan . --ai --ai-provider openai
qryon scan . --ai --ai-provider local

# Watch mode for continuous analysis
qryon watch .

# Generate SARIF output for CI/CD
qryon scan . --output sarif -f results.sarif
```

## Alternative Installation

If npm installation fails, try:

```bash
# Cargo (requires Rust)
cargo install qryon

# Shell script (Linux/macOS)
curl -fsSL https://raw.githubusercontent.com/bumahkib7/qryon/master/install.sh | bash

# Homebrew (macOS/Linux)
brew install bumahkib7/tap/qryon
```

## Documentation

Full documentation: https://github.com/bumahkib7/qryon

## License

MIT OR Apache-2.0
