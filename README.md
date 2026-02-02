# RMA - Rust Monorepo Analyzer

[![CI](https://github.com/bumahkib7/rust-monorepo-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/bumahkib7/rust-monorepo-analyzer/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/bumahkib7/rust-monorepo-analyzer)](https://github.com/bumahkib7/rust-monorepo-analyzer/releases)
[![npm](https://img.shields.io/npm/v/rma-cli)](https://www.npmjs.com/package/rma-cli)
[![crates.io](https://img.shields.io/crates/v/rma-cli.svg)](https://crates.io/crates/rma-cli)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fbumahkib7%2Frma-blue)](https://ghcr.io/bumahkib7/rma)
[![Homebrew](https://img.shields.io/badge/homebrew-bumahkib7%2Ftap%2Frma-orange)](https://github.com/bumahkib7/homebrew-tap)
[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

**Ultra-fast Rust-native code intelligence and security analysis platform for large enterprise monorepos.**

RMA leverages tree-sitter for polyglot parsing, rayon for parallelism, and tantivy for blazing-fast indexing to deliver sub-minute scans on million-LOC codebases.

## Quick Install

**npm (Node.js):**
```bash
npm install -g rma-cli
```

**Homebrew (macOS/Linux):**
```bash
brew tap bumahkib7/tap
brew install rma
```

**Cargo (Rust):**
```bash
cargo install rma-cli
```

**Shell Script (Linux/macOS):**
```bash
curl -fsSL https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.sh | bash

# Install specific version
VERSION=0.15.0 curl -fsSL https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.sh | bash
```

**Windows PowerShell:**
```powershell
iwr -useb https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.ps1 | iex
```

**Docker:**
```bash
docker run -v $(pwd):/workspace ghcr.io/bumahkib7/rma scan /workspace
```

**GitHub Actions:**
```yaml
- uses: bumahkib7/rust-monorepo-analyzer@v0.15.0
  with:
    path: '.'
    upload-sarif: true
```

**Pre-commit:**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bumahkib7/rust-monorepo-analyzer
    rev: v0.15.0
    hooks:
      - id: rma
```

## Supported Languages

| Language | Extensions | Security Rules | Metrics |
|----------|------------|----------------|---------|
| Rust | `.rs` | unsafe blocks, unwrap, panic | complexity, LOC |
| JavaScript | `.js`, `.jsx`, `.mjs` | XSS, injection, secrets | complexity, LOC |
| TypeScript | `.ts`, `.tsx` | XSS, injection, secrets | complexity, LOC |
| Python | `.py` | exec, shell injection, secrets | complexity, LOC |
| Go | `.go` | unsafe, SQL injection | complexity, LOC |
| Java | `.java` | injection, crypto issues | complexity, LOC |

## Features

- **Polyglot Support**: Rust, JavaScript/TypeScript, Python, Go, Java
- **Parallel Parsing**: Multi-threaded AST parsing with tree-sitter
- **Security Analysis**: Detect vulnerabilities, unsafe patterns, hardcoded secrets
- **Rich Diagnostics**: Rustc-style error output with source context and error codes
- **AI-Powered Analysis**: Optional AI-assisted vulnerability detection with `--ai` flag
- **Code Metrics**: Cyclomatic complexity, cognitive complexity, LOC
- **Fast Indexing**: Tantivy-based full-text search
- **Incremental Mode**: Only re-analyze changed files
- **Multiple Output Formats**: Text, JSON, SARIF, Compact, Markdown, GitHub
- **Real-time Watch Mode**: WebSocket-based live updates with interactive keyboard controls
- **HTTP API**: Daemon mode with WebSocket support for IDE integration
- **IDE Integrations**: VS Code, Neovim, JetBrains, and Web Dashboard
- **Doctor Command**: Health check for RMA installation (`rma doctor`)
- **Duplicate Detection**: Find copy-pasted functions across your codebase
- **WASM Plugins**: Extend with custom analysis rules
- **External Providers**: Optional integration with PMD for enhanced Java analysis
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

# Check installation health
rma doctor

# Scan only changed files in a PR
rma scan . --changed-only
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
| `doctor` | Check RMA installation health and configuration |
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
      --changed-only        Only scan files changed in git (for PR workflows)
  -j, --parallelism <N>     Number of parallel workers (0 = auto-detect)
  -l, --languages <LANGS>   Languages to scan (comma-separated)
      --providers <LIST>    Analysis providers (rma,pmd,oxlint) [default: rma]
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
      --no-initial-scan     Skip initial directory scan (only show changes)
      --errors-only         Only show errors, not warnings
  -q, --quiet               Suppress non-essential output
```

**Interactive Keyboard Shortcuts:**

| Key | Action |
|-----|--------|
| `q` / `c` | Quit watch mode |
| `r` | Force re-scan of all files |
| `s` | Show current statistics |
| `e` | Toggle errors-only mode |
| `p` | Pause/resume watching |
| `?` | Show help |

## Output Formats

| Format | Use Case |
|--------|----------|
| `text` | Human-readable terminal output with rustc-style diagnostics |
| `json` | Machine-readable for programmatic processing |
| `sarif` | GitHub Code Scanning, Azure DevOps integration |
| `compact` | Minimal output for CI logs |
| `markdown` | Documentation and reports |
| `github` | GitHub Actions workflow commands (annotations) |

### Rich Diagnostics Output

RMA produces rustc-style diagnostic output with error codes, source context, and underline highlighting:

```
warning[RMA-Q501]: Function has 105 lines (max: 100) - consider refactoring
  --> src/analyzer.rs:219:5
217 │     }
218 │
219 │     fn check(&self, parsed: &ParsedFile) -> Vec<Finding> {
    │     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ function too long
    ... (104 more lines)
   = note: rule: generic/long-function

critical[RMA-S005]: SQL query built with format! - use parameterized queries instead
  --> src/database.rs:42:9
40 │     let user_input = get_input();
41 │
42 │     format!(
    │     ^^^^^^^^ SQL query built from untrusted input
43 │         "SELECT * FROM users WHERE name = '{}'",
44 │         user_input
   = note: rule: rust/sql-injection
```

### Error Codes

| Code Range | Category |
|------------|----------|
| RMA-S001-S999 | Security issues (unsafe, XSS, injection, etc.) |
| RMA-Q001-Q999 | Quality issues (complexity, length, style) |
| RMA-T001-T999 | Style issues (TODO, console.log, etc.) |
| RMA-J001-J999 | Java external tool findings (PMD) |

### GitHub Actions Integration

RMA provides a GitHub Action for easy CI/CD integration with automatic SARIF upload to GitHub Security tab.

#### Basic Usage

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
        uses: bumahkib7/rust-monorepo-analyzer@v0.15.0
        with:
          path: '.'
          severity: 'warning'
          upload-sarif: 'true'
```

#### With PR Comments

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - name: Run RMA Security Scan
        uses: bumahkib7/rust-monorepo-analyzer@v0.15.0
        with:
          path: '.'
          format: 'sarif'
          severity: 'warning'
          upload-sarif: 'true'
          comment-on-pr: 'true'
```

#### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `format` | Output format (text, json, sarif, compact, markdown, github) | `sarif` |
| `severity` | Minimum severity (info, warning, error, critical) | `warning` |
| `languages` | Comma-separated languages to scan | (all) |
| `ai` | Enable AI-powered analysis | `false` |
| `verbose` | Enable verbose output | `false` |
| `upload-sarif` | Upload SARIF to GitHub Security tab | `true` |
| `show-annotations` | Show GitHub annotations for findings | `true` |
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
- `generic/duplicate-function` - Detects copy-pasted functions (10+ lines)
- `generic/insecure-crypto` - Detects MD5, SHA-1, DES, RC4, ECB usage

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
| WS | `/ws/watch` | WebSocket for real-time updates |

### Example Request

```bash
curl -X POST http://localhost:9876/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/repo", "languages": ["rust", "python"]}'
```

### WebSocket Real-time Updates

Connect to `/ws/watch` for real-time file change notifications and analysis results:

```javascript
const ws = new WebSocket('ws://localhost:9876/ws/watch');

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  switch (msg.type) {
    case 'FileChanged':
      console.log(`File changed: ${msg.data.path}`);
      break;
    case 'AnalysisComplete':
      console.log(`Analysis: ${msg.data.findings.length} findings`);
      break;
  }
};

// Start watching a directory
ws.send(JSON.stringify({ command: 'Watch', data: { path: '/path/to/repo' } }));
```

## IDE Integrations

RMA provides official integrations for popular editors and IDEs.

### VS Code Extension

```bash
# Install from VSIX
code --install-extension editors/vscode-rma/rma-vscode-*.vsix
```

Features:
- Real-time diagnostics as you type
- Problem panel integration
- Quick fixes and code actions
- Status bar with finding count

### Neovim Plugin

```lua
-- Using lazy.nvim
{
  dir = "editors/neovim-rma",
  config = function()
    require("rma").setup({
      daemon_url = "http://localhost:9876",
      auto_start_daemon = true,
    })
  end,
}
```

### JetBrains Plugin

Install from `editors/jetbrains-rma/` - supports IntelliJ IDEA, WebStorm, PyCharm, GoLand, and CLion.

### Web Dashboard

For browser-based real-time monitoring:

```bash
# Start the daemon
rma daemon

# Open the dashboard
open editors/web-dashboard/index.html
```

The web dashboard connects via WebSocket and shows live analysis results as you edit files.

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

## External Providers

RMA supports optional integration with external static analysis tools for enhanced language-specific coverage.

### PMD for Java

[PMD](https://pmd.github.io/) provides comprehensive Java static analysis with hundreds of rules for security, best practices, and code style.

**Enable PMD:**
```bash
# Use PMD alongside RMA's native rules
rma scan . --providers rma,pmd

# Configure PMD in rma.toml (see Configuration section)
```

**Requirements:**
- PMD 6.x or 7.x installed and available in PATH
- Or specify custom path in `rma.toml`

**PMD Rulesets:**
RMA uses PMD's security, error-prone, and best practices rulesets by default. You can customize which rulesets to use in the configuration.

### Available Providers

| Provider | Languages | Description |
|----------|-----------|-------------|
| `rma` | All | Built-in Rust-native rules (always enabled) |
| `pmd` | Java | PMD static analysis for Java |
| `oxlint` | JS/TS | Oxlint for JavaScript/TypeScript |
| `gosec` | Go | Gosec for Go security analysis |

### Gosec for Go

[Gosec](https://github.com/securego/gosec) is the Go Security Checker that inspects Go source code for security problems.

**Install Gosec:**
```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

**Enable Gosec:**
```bash
# Use gosec alongside RMA's native rules
rma scan . --providers rma,gosec
```

**Gosec Rules:**
Gosec detects common Go security issues including:
- G101-G110: Hardcoded credentials, bind to all interfaces
- G201-G204: SQL injection, command injection
- G301-G307: File permissions, file traversal
- G401-G505: Weak crypto, insecure TLS

## Configuration

Initialize configuration:

```bash
rma init
```

This creates `rma.toml`:

```toml
# Config format version (required)
config_version = 1

[scan]
include = ["src/**", "lib/**"]
exclude = ["node_modules/**", "target/**", "dist/**"]
max_file_size = 10485760

[rules]
enable = ["*"]
disable = ["js/console-log"]

[rulesets]
security = ["js/xss-sink", "js/timer-string-eval", "rust/unsafe-block"]
maintainability = ["generic/long-function", "generic/high-complexity"]

[profiles]
default = "balanced"

[profiles.strict]
max_function_lines = 50
max_complexity = 10

[allow]
unsafe_rust_paths = ["src/ffi/**"]

[baseline]
file = ".rma/baseline.json"
mode = "all"  # or "new-only"

# Optional: External providers configuration
# [providers]
# enabled = ["rma", "pmd"]  # Providers to use
#
# [providers.pmd]
# pmd_path = "/usr/local/bin/pmd"  # Path to PMD installation
# rulesets = ["category/java/security.xml", "category/java/bestpractices.xml"]
# timeout_ms = 120000  # 2 minute timeout
# min_priority = 3  # 1-5, lower is more severe
```

### Inline Suppression

Suppress specific findings with comments:

```javascript
// rma-ignore-next-line js/xss-sink reason="content is sanitized"
element.textContent = processedContent;

// rma-ignore generic/long-function reason="complex algorithm"
function processData() { /* ... */ }
```

```python
# rma-ignore-next-line python/hardcoded-secret reason="test fixture"
TEST_API_KEY = "test-key-12345"
```
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
- [x] Watch mode with interactive controls
- [x] HTTP API daemon with WebSocket support
- [x] WASM plugin system
- [x] AI-powered analysis
- [x] One-command installation
- [x] GitHub Actions integration
- [x] VS Code extension
- [x] Neovim plugin
- [x] JetBrains plugin
- [x] Web Dashboard
- [x] Doctor command
- [x] Duplicate function detection
- [ ] LSP integration
- [ ] Cloud SaaS deployment

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
