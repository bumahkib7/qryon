# RMA - Rust Monorepo Analyzer

<div align="center">

**Find security vulnerabilities in seconds, not minutes.**

[![CI](https://github.com/bumahkib7/rust-monorepo-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/bumahkib7/rust-monorepo-analyzer/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/rma-cli)](https://www.npmjs.com/package/rma-cli)
[![crates.io](https://img.shields.io/crates/v/rma-cli.svg)](https://crates.io/crates/rma-cli)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

</div>

```bash
# Install in 10 seconds
npm install -g rma-cli

# Find vulnerabilities instantly
rma scan .
```

<p align="center">
  <img src="pics/demo.gif" alt="RMA scanning a codebase and finding vulnerabilities" width="700">
</p>

---

## Why RMA?

| Feature | RMA | Semgrep OSS | CodeQL |
|---------|:---:|:-----------:|:------:|
| **Scan 1M lines** | 45s | 8+ min | 15+ min |
| **Languages** | 28 | 30+ | 12 |
| **Setup** | `npm i -g rma-cli` | Docker/pip | Complex |
| **Rules** | 647+ | 2500+ | Varies |
| **Cross-file taint** | Yes | Pro only | Yes |
| **Single binary** | Yes | No | No |
| **Price** | Free | Free/Paid | Free |

**RMA is 10x faster** because it compiles Semgrep rules to native Rust matchers at build time - no interpreter overhead.

---

## Quick Start

```bash
# Scan your project
rma scan .

# Interactive TUI - browse findings with vim keys
rma scan . --interactive

# CI/CD mode - SARIF output for GitHub Security tab
rma scan . --output sarif -f results.sarif

# Watch mode - re-scan on file changes
rma watch .
```

<details>
<summary><strong>More installation methods</strong></summary>

**Homebrew (macOS/Linux):**
```bash
brew tap bumahkib7/tap && brew install rma
```

**Cargo (Rust):**
```bash
cargo install rma-cli
```

**Docker:**
```bash
docker run -v $(pwd):/workspace ghcr.io/bumahkib7/rma scan /workspace
```

**Shell Script:**
```bash
curl -fsSL https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.sh | bash
```

**GitHub Actions:**
```yaml
- uses: bumahkib7/rust-monorepo-analyzer@v0.16.0
  with:
    path: '.'
    upload-sarif: true
```

</details>

---

## What It Finds

```
critical[RMA-S005]: SQL query built with format! - use parameterized queries
  --> src/database.rs:42:9
40 │     let user_input = get_input();
41 │
42 │     format!(
   │     ^^^^^^^^ SQL query built from untrusted input
43 │         "SELECT * FROM users WHERE name = '{}'",
44 │         user_input
   = note: rule: rust/sql-injection
```

### Security Detection

- **Injection attacks** - SQL, command, XSS, LDAP, template injection
- **Server-side vulnerabilities** - SSRF, path traversal, deserialization
- **Hardcoded secrets** - API keys, passwords, tokens
- **Cryptographic issues** - Weak algorithms (MD5, SHA-1, DES), insecure modes
- **Dependency CVEs** - Real-time OSV.dev integration for Cargo, npm, PyPI, Go, Maven

### Supported Languages

| Language | Security Rules | Frameworks |
|----------|----------------|------------|
| **Rust** | unsafe, injection, crypto | Actix, Axum, Rocket |
| **JavaScript/TypeScript** | XSS, injection, secrets | Express, React, Next.js |
| **Python** | exec, injection, secrets | Django, Flask, FastAPI |
| **Go** | unsafe, SQL injection | Gin, Echo, GORM |
| **Java** | injection, crypto, deser | Spring, Jakarta |

Plus 23 more languages with parsing and metrics support.

---

## Interactive TUI

Browse findings, call graphs, and taint flows with keyboard navigation:

```bash
rma scan . --interactive
```

<p align="center">
  <img src="pics/tui-findings.png" alt="Interactive TUI showing findings" width="600">
</p>

**Keyboard shortcuts:** `j/k` navigate, `Tab` switch tabs, `s` filter severity, `/` search, `q` quit

---

## GitHub Actions

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
      - uses: bumahkib7/rust-monorepo-analyzer@v0.16.0
        with:
          path: '.'
          upload-sarif: true
```

Findings appear in the GitHub Security tab automatically.

---

## RMA Dashboard - Team Features

Love the CLI? **[RMA Dashboard](https://rma-dashboard.bukhari-kibuka7.workers.dev)** adds powerful team features:

| Feature | CLI | Dashboard |
|---------|:---:|:---------:|
| Scan & detect | Yes | Yes |
| Historical trends | - | Yes |
| AI-powered explanations | - | Yes |
| Auto-fix suggestions | - | Yes |
| Team collaboration | - | Yes |
| Baseline diffs | - | Yes |
| PR integration | - | Yes |
| RBAC & audit logs | - | Yes |

**[Try RMA Dashboard free →](https://rma-dashboard.bukhari-kibuka7.workers.dev)**

---

## Advanced Features

<details>
<summary><strong>Cross-File Taint Tracking</strong></summary>

Track data flows across file and function boundaries:

```bash
rma flows . --evidence --group-by sink-type
```

- Forward taint propagation
- Path-sensitive analysis
- Sanitizer recognition
- Symbolic path conditions

</details>

<details>
<summary><strong>Dependency Vulnerability Scanning</strong></summary>

Integrated with [OSV.dev](https://osv.dev) for real-time CVE detection:

```bash
rma security .
```

Supports: Cargo, npm, PyPI, Go modules, Maven

</details>

<details>
<summary><strong>HTTP API (Daemon Mode)</strong></summary>

```bash
rma daemon --port 9876
```

REST API + WebSocket for IDE integration.

</details>

<details>
<summary><strong>IDE Integrations</strong></summary>

- **VS Code** - Real-time diagnostics
- **Neovim** - Native plugin
- **JetBrains** - IntelliJ, WebStorm, PyCharm

</details>

<details>
<summary><strong>WASM Plugins</strong></summary>

Extend with custom analysis rules:

```bash
rma plugin install ./my-plugin.wasm
```

</details>

---

## How It Works

RMA compiles [Semgrep community rules](https://github.com/semgrep/semgrep-rules) at **build time** into optimized native matchers:

```
┌─────────────────────────────────────────────────────────┐
│                     BUILD TIME                          │
│  semgrep-rules/*.yaml  →  build.rs  →  compiled_rules  │
│                                           (embedded)    │
└─────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────┐
│                      RUNTIME                            │
│  source.rs  →  tree-sitter  →  AST  →  pattern match  │
│                                               ↓         │
│                                           Findings      │
└─────────────────────────────────────────────────────────┘
```

**Result:** No interpreter overhead. No Semgrep dependency. Single binary.

---

## Configuration

```bash
rma init  # Creates rma.toml
```

```toml
[scan]
include = ["src/**"]
exclude = ["node_modules/**", "target/**"]

[rules]
enable = ["*"]
disable = ["js/console-log"]

[profiles.strict]
max_function_lines = 50
max_complexity = 10
```

Inline suppression:
```javascript
// rma-ignore-next-line js/xss-sink reason="content is sanitized"
element.textContent = processedContent;
```

---

## Benchmarks

```bash
hyperfine 'rma scan /path/to/repo' 'semgrep --config auto /path/to/repo'
```

On a 500K LOC monorepo:
- **RMA**: 23 seconds
- **Semgrep**: 4 minutes 12 seconds

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
make build    # Build all crates
make test     # Run tests
make lint     # Run lints
```

## License

MIT or Apache-2.0, at your option.

---

<div align="center">

**[Documentation](https://github.com/bumahkib7/rust-monorepo-analyzer/wiki)** · **[Dashboard](https://rma-dashboard.bukhari-kibuka7.workers.dev)** · **[Issues](https://github.com/bumahkib7/rust-monorepo-analyzer/issues)**

Made with Rust

</div>
