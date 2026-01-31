# RMA - Rust Monorepo Analyzer

[![CI](https://github.com/bumahkib7/rust-monorepo-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/bumahkib7/rust-monorepo-analyzer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/bumahkib7/rust-monorepo-analyzer)](https://github.com/bumahkib7/rust-monorepo-analyzer/releases)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

**Ultra-fast Rust-native code intelligence and security analysis platform for large enterprise monorepos.**

RMA leverages tree-sitter for polyglot parsing, rayon for parallelism, and tantivy for blazing-fast indexing to deliver sub-minute scans on million-LOC codebases.

## Quick Install

**Linux/macOS (one command):**
```bash
curl -fsSL https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.sh | bash
```

**Windows PowerShell:**
```powershell
iwr -useb https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.ps1 | iex
```

**Cargo:**
```bash
cargo install rma-cli
```

**Docker:**
```bash
docker run -v $(pwd):/workspace ghcr.io/bumahkib7/rust-monorepo-analyzer scan /workspace
```

## Features

- **Polyglot Support**: Rust, JavaScript/TypeScript, Python, Go, Java
- **Parallel Parsing**: Multi-threaded AST parsing with tree-sitter
- **Security Analysis**: Detect vulnerabilities, unsafe patterns, hardcoded secrets
- **AI-Powered Analysis**: Optional AI-assisted vulnerability detection with `--ai` flag
- **Code Metrics**: Cyclomatic complexity, cognitive complexity, LOC
- **Fast Indexing**: Tantivy-based full-text search
- **Incremental Mode**: Only re-analyze changed files
- **Multiple Output Formats**: Text, JSON, SARIF, Compact, Markdown
- **Watch Mode**: Real-time analysis on file changes
- **HTTP API**: Daemon mode for IDE integration
- **WASM Plugins**: Extend with custom analysis rules
- **Shell Completions**: Bash, Zsh, Fish, PowerShell, Elvish

## Quick Start

```bash
# Scan current directory
rma scan .

# Scan with AI-powered analysis
rma scan ./src --ai

# Scan with JSON output for CI/CD
rma scan . --output json -f results.json

# Scan with SARIF output for GitHub Code Scanning
rma scan . --output sarif -f results.sarif

# Watch mode for continuous analysis
rma watch .

# Search indexed code
rma search "TODO" --type content

# View statistics
rma stats
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan a repository for security issues and metrics |
| `watch` | Watch for file changes and re-analyze in real-time |
| `search` | Search the index for files or findings |
| `stats` | Show index and analysis statistics |
| `init` | Initialize RMA configuration in current directory |
| `daemon` | Start HTTP API server for IDE integration |
| `plugin` | Manage WASM analysis plugins |
| `config` | View and modify configuration |
| `completions` | Generate shell completions |

### Scan Options

```
rma scan [PATH] [OPTIONS]

Options:
  -o, --output <FORMAT>     Output format: text, json, sarif, compact, markdown [default: text]
  -f, --output-file <FILE>  Output file (stdout if not specified)
  -s, --severity <LEVEL>    Minimum severity: info, warning, error, critical
  -i, --incremental         Enable incremental mode (only scan changed files)
  -j, --parallelism <N>     Number of parallel workers (0 = auto-detect)
  -l, --languages <LANGS>   Languages to scan (comma-separated)
      --ai                  Enable AI-powered vulnerability analysis
      --no-progress         Disable progress bars
  -v, --verbose             Increase verbosity (-v, -vv, -vvv)
  -q, --quiet               Suppress non-essential output
```

### Watch Options

```
rma watch [PATH] [OPTIONS]

Options:
  -d, --debounce <MS>       Debounce delay in milliseconds [default: 500]
  -l, --languages <LANGS>   Languages to watch
      --clear               Clear screen on each change
```

## Output Formats

| Format | Use Case |
|--------|----------|
| `text` | Human-readable terminal output with colors |
| `json` | Machine-readable for programmatic processing |
| `sarif` | GitHub Code Scanning, Azure DevOps integration |
| `compact` | Minimal output for CI logs |
| `markdown` | Documentation and reports |

### GitHub Actions Integration

RMA provides a reusable GitHub Action for easy CI/CD integration with automatic SARIF upload to GitHub Security tab.

#### Quick Setup (Reusable Workflow)

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    uses: bumahkib7/rust-monorepo-analyzer/.github/workflows/rma-scan-reusable.yml@master
    permissions:
      contents: read
      security-events: write
    with:
      path: './src'
      severity: 'warning'
      upload-sarif: true
```

#### Composite Action (More Control)

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - name: Run RMA Security Scan
        uses: bumahkib7/rust-monorepo-analyzer/.github/actions/rma-scan@master
        with:
          path: '.'
          format: 'sarif'
          severity: 'warning'
          upload-sarif: 'true'
```

#### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `format` | Output format (text, json, sarif, compact, markdown) | `sarif` |
| `severity` | Minimum severity (info, warning, error, critical) | `warning` |
| `languages` | Comma-separated languages to scan | (all) |
| `ai` | Enable AI-powered analysis | `false` |
| `verbose` | Enable verbose output | `false` |
| `upload-sarif` | Upload SARIF to GitHub Security tab | `true` |
| `fail-on-findings` | Fail workflow if findings detected | `false` |
| `version` | RMA version to use | `latest` |

#### Action Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to generated SARIF file |
| `findings-count` | Number of security findings detected |

#### Manual SARIF Upload

```yaml
- name: Run RMA Security Scan
  run: rma scan . --output sarif -f results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Architecture

```
rust-monorepo-analyzer/
├── crates/
│   ├── common/      # Shared types and utilities
│   ├── parser/      # Tree-sitter based polyglot parser
│   ├── analyzer/    # Security and code analysis engine
│   ├── indexer/     # Tantivy/Sled based indexing
│   ├── cli/         # Command-line interface
│   ├── daemon/      # HTTP API server (Axum)
│   ├── plugins/     # WASM plugin runtime (Wasmtime)
│   ├── lsp/         # Language Server Protocol
│   └── ai/          # AI-powered analysis
```

### Component Overview

| Crate | Purpose |
|-------|---------|
| `rma-common` | Core types: Language, Severity, Finding, Config |
| `rma-parser` | Parallel AST parsing with tree-sitter |
| `rma-analyzer` | Security rules and metrics computation |
| `rma-indexer` | Full-text search and incremental updates |
| `rma-cli` | User-facing CLI binary |
| `rma-daemon` | Axum-based HTTP API server |
| `rma-plugins` | Wasmtime-based WASM plugin system |
| `rma-lsp` | Language Server Protocol implementation |
| `rma-ai` | AI-powered vulnerability detection |

## Security Rules

### Rust
- `rust/unsafe-block` - Detects unsafe blocks requiring manual review
- `rust/unwrap-used` - Detects .unwrap() calls that may panic
- `rust/panic-used` - Detects panic! macro usage

### JavaScript/TypeScript
- `js/dynamic-code` - Detects dangerous dynamic code execution
- `js/innerHTML-xss` - Detects innerHTML usage (XSS risk)
- `js/hardcoded-secret` - Detects hardcoded credentials

### Python
- `python/exec-usage` - Detects exec/compile calls
- `python/shell-injection` - Detects shell=True patterns
- `python/hardcoded-secret` - Detects hardcoded credentials

### Go
- `go/unsafe-usage` - Detects unsafe package usage
- `go/sql-injection` - Detects SQL injection patterns

### Generic (All Languages)
- `generic/todo-fixme` - Detects TODO/FIXME comments
- `generic/long-function` - Detects functions over 100 lines
- `generic/high-complexity` - Detects high cyclomatic complexity
- `generic/hardcoded-secret` - Detects API keys and passwords

## HTTP API (Daemon Mode)

Start the daemon:

```bash
rma daemon --host 127.0.0.1 --port 9876
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/scan` | Scan a directory |
| POST | `/api/v1/analyze` | Analyze a single file |
| GET | `/api/v1/search` | Search indexed files |
| GET | `/api/v1/stats` | Get daemon statistics |
| POST | `/api/v1/index` | Trigger re-indexing |

### Example Request

```bash
curl -X POST http://localhost:9876/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/repo", "languages": ["rust", "python"]}'
```

## Plugin System

RMA supports WASM plugins for custom analysis rules:

```bash
# List installed plugins
rma plugin list

# Install a plugin
rma plugin install ./my-plugin.wasm

# Test a plugin
rma plugin test my-plugin --file src/main.rs

# Remove a plugin
rma plugin remove my-plugin
```

## Configuration

Initialize configuration:

```bash
rma init
```

This creates `.rma/config.json`:

```json
{
  "exclude_patterns": [
    "**/node_modules/**",
    "**/target/**",
    "**/vendor/**",
    "**/.git/**"
  ],
  "languages": [],
  "min_severity": "warning",
  "max_file_size": 10485760,
  "parallelism": 0,
  "incremental": true,
  "ai": {
    "enabled": false,
    "provider": "openai",
    "model": "gpt-4"
  }
}
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `RMA_CONFIG` | Path to config file |
| `RMA_LOG` | Log level (trace, debug, info, warn, error) |
| `OPENAI_API_KEY` | API key for AI-powered analysis |
| `RMA_NO_COLOR` | Disable colored output |

## Shell Completions

Generate completions for your shell:

```bash
# Bash
rma completions bash > ~/.local/share/bash-completion/completions/rma

# Zsh
rma completions zsh > ~/.zfunc/_rma

# Fish
rma completions fish > ~/.config/fish/completions/rma.fish

# PowerShell
rma completions powershell > $PROFILE.CurrentUserAllHosts
```

## Development

```bash
# Build all crates
make build

# Run tests
make test

# Run lints
make lint

# Format code
make fmt

# Full CI check
make ci

# Scan RMA's own codebase
make self-scan

# Build documentation
make docs
```

## Benchmarks

```bash
# Run benchmarks
make bench

# Compare with Semgrep
hyperfine 'rma scan /path/to/repo' 'semgrep --config auto /path/to/repo'
```

## Roadmap

- [x] Multi-language tree-sitter parsing
- [x] Parallel analysis with rayon
- [x] SARIF output for CI/CD
- [x] Watch mode
- [x] HTTP API daemon
- [x] WASM plugin system
- [x] AI-powered analysis
- [x] One-command installation
- [x] GitHub Actions integration
- [ ] VS Code extension
- [ ] LSP integration
- [ ] Cloud SaaS deployment

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
