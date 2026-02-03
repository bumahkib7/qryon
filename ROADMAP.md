# RMA Roadmap

This document outlines the evolution of RMA (Rust Monorepo Analyzer) from its initial release to the current version, and what's planned for the future.

## Version History

### Phase 1: Foundation (v0.1.0 - v0.2.0)

**v0.1.0** — Initial Release
- Multi-language support: Rust, JavaScript, TypeScript, Python, Go, Java
- Tree-sitter based parsing for accurate AST analysis
- Security and code quality rules
- SARIF output for GitHub Security tab
- Watch mode for real-time analysis
- HTTP API daemon
- Configuration via `rma.toml`
- Profiles: fast, balanced, strict

**v0.2.0** — Configuration & CI
- Config versioning (`config_version = 1`)
- Stable fingerprints for baseline comparisons
- Rulesets (security, maintainability)
- Inline suppression (`// rma-ignore-next-line`)
- GitHub Actions integration

---

### Phase 2: Security Rules (v0.3.0 - v0.4.0)

**v0.3.0** — Secret Detection
- 8 new security rules across all languages
- Secret detection: API keys, AWS keys, GitHub tokens, private keys
- Insecure crypto detection: MD5, SHA-1, DES, RC4, ECB
- Automatic Homebrew tap updates

**v0.4.x** — Polish
- SARIF output improvements
- Better error messages
- Bug fixes and stability

---

### Phase 3: Rich Diagnostics (v0.5.0 - v0.6.0)

**v0.5.0** — Developer Experience
- Rustc-style diagnostics with code snippets and suggestions
- GitHub Actions output format (`--format github`)

**v0.6.0** — Real-time Monitoring
- WebSocket endpoint for real-time file watching (`/ws/watch`)
- Web dashboard for browser-based monitoring
- Interactive keyboard shortcuts in watch mode

---

### Phase 4: Native JS/TS Analysis (v0.7.0 - v0.9.0)

**v0.7.0** — Oxc Integration
- Native Oxc integration for JS/TS (no external binaries required)
- Gosec provider for Go security analysis
- Test file exclusion from secret detection
- 65 total rules

**v0.8.0 - v0.9.0** — Performance
- Rule pre-filtering with HashMap for O(1) lookup
- Single-pass AST traversal
- Pre-compiled regex patterns

---

### Phase 5: Vulnerability Scanning (v0.10.0 - v0.12.0)

**v0.12.0** — Security Audit
- `rma audit` command for comprehensive vulnerability assessment
- OSV provider for multi-language dependency scanning
- RustSec provider for Rust advisory database

---

### Phase 6: Cross-File Analysis (v0.13.0 - v0.14.0)

**v0.13.0** — Import Resolution
- Cross-file analysis (`--cross-file`)
- Import resolution and call graph construction
- Taint flow tracking through function parameters
- 20+ new security rules
- Diff-aware analysis (`--diff`)
- HTML report generation
- GitHub Action (`action.yml`)

**v0.14.0** — Typestate Analysis
- Typestate analysis framework (use-after-close, double-lock, etc.)
- Interactive TUI for browsing findings
- Smart progress display with ETA
- Powerful filtering: `--severity`, `--rules`, `--category`, `--search`
- Output limiting: `--limit N`, `--group-by`

---

### Phase 7: Enterprise Features (v0.15.0 - v0.16.0)

**v0.15.0** — GitHub Integration
- SARIF scanned files summary for GitHub Code Scanning
- Dedicated RMA scan workflow
- Open source community files (CODEOWNERS, CODE_OF_CONDUCT, SECURITY.md)

**v0.16.0** — Enhanced TUI & Caching *(Current)*
- Call Graph Statistics Panel
- Security Classification Badges (sources, sinks, sanitizers)
- Source→Sink flow highlighting with `⚠` warnings
- Analysis caching for faster re-scans
- Test files excluded by default (`--include-tests` to opt-in)

---

## Current Stats (v0.16.0)

| Metric | Value |
|--------|-------|
| Supported Languages | 6 (JavaScript, TypeScript, Python, Rust, Go, Java) |
| Security Rules | 647+ |
| Tree-sitter Grammars | 30+ |
| Crates | 10 |
| Output Formats | SARIF, JSON, GitHub, HTML, JUnit XML |

---

## What's Next

### v0.17.0 (In Progress)

- [ ] All 10 crates publishing to crates.io
- [ ] Improved test exclusion patterns
- [ ] Performance optimizations for large monorepos

### v0.18.0 (Planned)

- [ ] **Full LSP Integration** — Real-time diagnostics in any editor
- [ ] **Auto-fix suggestions** — `rma fix` command with safe transformations
- [ ] **Baseline management** — Track and suppress legacy issues

### v0.19.0 (Planned)

- [ ] **Reachability analysis** — Only flag vulnerabilities in reachable code paths
- [ ] **Custom rule builder** — YAML-based rule authoring with validation
- [ ] **Team dashboards** — Historical trends and metrics

---

## Long-term Vision

### Cloud SaaS Platform
- Hosted scanning service
- GitHub/GitLab/Bitbucket integrations
- Team collaboration features
- Centralized policy management

### Advanced Analysis
- Inter-procedural taint tracking
- Context-sensitive analysis
- Machine learning for false positive reduction
- Supply chain security (SBOM generation)

### Ecosystem
- VS Code extension (✅ Done)
- Neovim plugin (✅ Done)
- JetBrains plugin (✅ Done)
- Pre-commit hooks
- Monorepo-aware caching

---

## Completed Milestones

- [x] Multi-language tree-sitter parsing
- [x] Parallel analysis with rayon
- [x] SARIF output for CI/CD
- [x] Watch mode with interactive controls
- [x] HTTP API daemon with WebSocket support
- [x] WASM plugin system
- [x] AI-powered analysis
- [x] One-command installation (npm, cargo, brew)
- [x] GitHub Actions integration
- [x] VS Code extension
- [x] Neovim plugin
- [x] JetBrains plugin
- [x] Web Dashboard
- [x] Doctor command
- [x] Cross-file taint analysis
- [x] Interactive TUI
- [x] Analysis caching

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas for contribution:
- New security rules (especially for underserved languages)
- Performance improvements
- Documentation and examples
- Bug fixes and testing

---

## Feedback

Have ideas for the roadmap? Open a [GitHub Discussion](https://github.com/bumahkib7/rust-monorepo-analyzer/discussions) or file an issue!
