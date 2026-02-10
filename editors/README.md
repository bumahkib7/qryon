# Qryon Editor Integrations

This directory contains IDE and editor integrations for Qryon.

## Overview

| Editor | Method | Status | Directory |
|--------|--------|--------|-----------|
| **VS Code** | LSP | Ready | `vscode/` |
| **Neovim** | LSP | Ready | `neovim/` |
| **JetBrains** | WebSocket | Ready | `jetbrains/` |
| **Web Dashboard** | WebSocket | Ready | `web-dashboard/` |

## Quick Start

### Prerequisites

1. Build Qryon binaries:
```bash
cargo build --release
```

2. Install binaries:
```bash
# LSP server (for VS Code, Neovim)
cp target/release/rma-lsp ~/.cargo/bin/

# CLI (for daemon, watch mode)
cp target/release/qryon ~/.cargo/bin/
```

### VS Code

```bash
cd editors/vscode
npm install
npm run compile
npm run package
code --install-extension rma-vscode-0.6.0.vsix
```

### Neovim

```lua
-- In your init.lua
vim.opt.runtimepath:append('/path/to/qryon/editors/neovim')
require('rma').setup()
```

### JetBrains IDEs

```bash
# 1. Start daemon
qryon daemon --port 8080

# 2. Build plugin
cd editors/jetbrains
./gradlew buildPlugin

# 3. Install from build/distributions/
```

### Web Dashboard

```bash
# 1. Start daemon
qryon daemon --port 8080

# 2. Open dashboard
open editors/web-dashboard/index.html
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         IDE / EDITOR                             │
├─────────────────┬─────────────────┬─────────────────────────────┤
│    VS Code      │     Neovim      │   JetBrains / Web          │
│  (Extension)    │    (Plugin)     │   (Plugin / Browser)        │
└────────┬────────┴────────┬────────┴────────────┬────────────────┘
         │                 │                      │
         │ LSP             │ LSP                  │ WebSocket
         │                 │                      │
         ▼                 ▼                      ▼
┌─────────────────────────────┐      ┌─────────────────────────────┐
│        rma-lsp              │      │        qryon daemon         │
│   (Language Server)         │      │      (HTTP + WebSocket)     │
└──────────────┬──────────────┘      └──────────────┬──────────────┘
               │                                    │
               └────────────────┬───────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   Qryon Core Engine   │
                    │  - Parser (tree-sitter)│
                    │  - Analyzer (45+ rules)│
                    │  - RustSec integration │
                    └───────────────────────┘
```

## Communication Protocols

### LSP (VS Code, Neovim)

Standard Language Server Protocol over stdio:
- `textDocument/publishDiagnostics` - Send findings
- `textDocument/didOpen` - File opened
- `textDocument/didChange` - File changed
- `textDocument/didSave` - File saved

### WebSocket (JetBrains, Web)

Custom JSON protocol over WebSocket:

```
Client → Server: { command: "Watch", data: { path: "./src" } }
Server → Client: { type: "AnalysisComplete", data: { findings: [...] } }
```

### REST API (Daemon)

```
GET  /health           - Health check
POST /api/v1/scan      - Scan directory
POST /api/v1/analyze   - Analyze file
GET  /api/v1/search    - Search findings
GET  /api/v1/stats     - Get statistics
```

## Feature Comparison

| Feature | VS Code | Neovim | JetBrains | Web |
|---------|---------|--------|-----------|-----|
| Real-time diagnostics | Yes | Yes | Yes | Yes |
| Inline annotations | Yes | Yes | Yes | No |
| Code actions | Yes | Yes | Soon | No |
| Quick fixes | Soon | Soon | Soon | No |
| Project-wide scan | Yes | Yes | Yes | Yes |
| RustSec integration | Yes | Yes | Yes | Yes |
| Custom rules | Soon | Soon | Soon | Soon |
| Statistics view | No | No | No | Yes |

## Troubleshooting

### LSP not starting

```bash
# Check if binary exists and is executable
which rma-lsp
rma-lsp --version

# Check LSP logs in editor
# VS Code: View → Output → Qryon
# Neovim: :LspLog
```

### WebSocket not connecting

```bash
# Check if daemon is running
curl http://localhost:8080/health

# Check daemon logs
qryon daemon --port 8080 -vv
```

### No findings showing

```bash
# Test CLI directly
qryon scan ./src

# Check if file type is supported
# Supported: .rs, .js, .ts, .tsx, .jsx, .py, .go, .java
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Make changes to editor integrations
4. Test with the actual editor
5. Submit a pull request
