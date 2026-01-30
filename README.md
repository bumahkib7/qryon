# RMA - Rust Monorepo Analyzer

[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

**Ultra-fast Rust-native code intelligence and security analysis platform for large enterprise monorepos.**

RMA leverages tree-sitter for polyglot parsing, rayon for parallelism, and tantivy for blazing-fast indexing to deliver sub-minute scans on million-LOC codebases.

## Features

- **Polyglot Support**: Rust, JavaScript/TypeScript, Python, Go, Java
- **Parallel Parsing**: Multi-threaded AST parsing with tree-sitter
- **Security Analysis**: Detect vulnerabilities, unsafe patterns, hardcoded secrets
- **Code Metrics**: Cyclomatic complexity, cognitive complexity, LOC
- **Fast Indexing**: Tantivy-based full-text search
- **Incremental Mode**: Only re-analyze changed files
- **Multiple Output Formats**: Text, JSON, SARIF
- **Watch Mode**: Real-time analysis on file changes
- **HTTP API**: Daemon mode for IDE integration

## Installation

```bash
# From source
git clone https://github.com/bumahkib7/rust-monorepo-analyzer.git
cd rust-monorepo-analyzer
cargo build --release

# Install binary
cargo install --path crates/cli
```

## Quick Start

```bash
# Scan current directory
rma scan

# Scan specific path with JSON output
rma scan /path/to/repo --output json -f results.json

# Scan only Rust and Python files
rma scan --languages rust,python

# Watch mode for continuous analysis
rma watch /path/to/repo

# Initialize configuration
rma init
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `scan` | Scan a repository for security issues and metrics |
| `search` | Search the index for files or findings |
| `stats` | Show index statistics |
| `init` | Initialize RMA configuration |
| `watch` | Watch for file changes and re-analyze |

### Scan Options

```
rma scan [PATH] [OPTIONS]

Options:
  -o, --output <FORMAT>     Output format: text, json, sarif [default: text]
  -f, --output-file <FILE>  Output file (stdout if not specified)
  -s, --severity <LEVEL>    Minimum severity: info, warning, error, critical
  -i, --incremental         Enable incremental mode
  -j, --parallelism <N>     Number of parallel workers (0 = auto)
  -l, --languages <LANGS>   Languages to scan (comma-separated)
  -v, --verbose             Increase verbosity
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
│   └── daemon/      # HTTP API server
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

## Security Rules

### Rust
- `rust/unsafe-block` - Detects unsafe blocks requiring manual review
- `rust/unwrap-used` - Detects .unwrap() calls that may panic
- `rust/panic-used` - Detects panic! macro usage

### JavaScript/TypeScript
- `js/dynamic-code-execution` - Detects dangerous code evaluation patterns
- `js/innerhtml-xss` - Detects innerHTML usage (XSS risk)
- `js/console-log` - Detects console.log statements

### Python
- `python/dynamic-execution` - Detects exec/compile calls
- `python/shell-injection` - Detects shell=True patterns
- `python/hardcoded-secret` - Detects hardcoded credentials

### Generic
- `generic/todo-fixme` - Detects TODO/FIXME comments
- `generic/long-function` - Detects functions over 100 lines
- `generic/high-complexity` - Detects high cyclomatic complexity

## HTTP API (Daemon Mode)

Start the daemon:

```bash
rma-daemon --host 127.0.0.1 --port 9876
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/scan` | Scan a directory |
| POST | `/api/v1/analyze` | Analyze a single file |
| GET | `/api/v1/search` | Search indexed files |
| GET | `/api/v1/stats` | Get daemon statistics |

### Example Request

```bash
curl -X POST http://localhost:9876/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/repo"}'
```

## Configuration

Create `.rma/config.json` in your project:

```json
{
  "exclude_patterns": [
    "**/node_modules/**",
    "**/target/**",
    "**/vendor/**"
  ],
  "languages": [],
  "min_severity": "warning",
  "max_file_size": 10485760,
  "parallelism": 0,
  "incremental": false
}
```

## Benchmarks

Run benchmarks:

```bash
cargo bench
```

Compare with Semgrep:

```bash
hyperfine 'rma scan /path/to/repo' 'semgrep --config auto /path/to/repo'
```

## Development

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -p rma-cli -- scan .

# Format code
cargo fmt

# Lint
cargo clippy
```

## Roadmap

- [ ] WASM plugin system for custom rules
- [ ] LSP integration
- [ ] AI-powered vulnerability detection
- [ ] Cloud SaaS deployment
- [ ] GitHub Actions integration
- [ ] VS Code extension

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
