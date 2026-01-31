# CLI Reference

Complete command-line reference for RMA (Rust Monorepo Analyzer).

## Global Options

These options can be used with any command:

```
-v, --verbose       Increase logging verbosity (can be repeated: -v, -vv, -vvv)
-q, --quiet         Suppress non-essential output
    --no-color      Disable colored output
-c, --config <PATH> Path to configuration file
-h, --help          Print help information
-V, --version       Print version information
```

## Commands

### scan

Scan a repository for security issues, code smells, and metrics.

```bash
rma scan [PATH] [OPTIONS]
```

**Arguments:**
- `PATH` - Directory to scan (default: current directory)

**Options:**
```
-o, --output <FORMAT>       Output format [default: text]
                            Values: text, json, sarif, compact, markdown
-f, --output-file <FILE>    Write output to file (stdout if not specified)
-s, --severity <LEVEL>      Minimum severity to report [default: info]
                            Values: info, warning, error, critical
-i, --incremental           Only scan files changed since last scan
-j, --parallelism <N>       Number of parallel workers [default: 0 (auto)]
-l, --languages <LANGS>     Comma-separated list of languages to scan
                            Values: rust, javascript, typescript, python, go, java
    --ai                    Enable AI-powered vulnerability analysis
    --no-progress           Disable progress bars
    --no-index              Skip indexing (faster, but no search)
```

**Examples:**
```bash
# Basic scan
rma scan .

# Scan with AI analysis
rma scan ./src --ai

# Only critical and error severity
rma scan . -s error

# JSON output to file
rma scan . -o json -f results.json

# SARIF for GitHub Code Scanning
rma scan . -o sarif -f results.sarif

# Only Rust and Python files
rma scan . -l rust,python

# Incremental scan (only changed files)
rma scan . -i

# Use 4 parallel workers
rma scan . -j 4
```

### watch

Watch for file changes and re-analyze in real-time.

```bash
rma watch [PATH] [OPTIONS]
```

**Arguments:**
- `PATH` - Directory to watch (default: current directory)

**Options:**
```
-d, --debounce <MS>     Debounce delay in milliseconds [default: 500]
-l, --languages <LANGS> Comma-separated list of languages to watch
    --clear             Clear screen on each change
```

**Examples:**
```bash
# Watch current directory
rma watch .

# Watch with screen clear
rma watch . --clear

# Custom debounce (1 second)
rma watch . -d 1000

# Only watch Rust files
rma watch . -l rust
```

### search

Search the index for files, findings, or content.

```bash
rma search <QUERY> [OPTIONS]
```

**Arguments:**
- `QUERY` - Search query string

**Options:**
```
-t, --type <TYPE>       Search type [default: content]
                        Values: file, content, finding
-l, --limit <N>         Maximum results to return [default: 20]
-o, --output <FORMAT>   Output format [default: text]
                        Values: text, json
```

**Examples:**
```bash
# Search for content
rma search "TODO"

# Search for files by name
rma search "main.rs" -t file

# Search findings
rma search "unsafe" -t finding

# Limit results
rma search "error" -l 10

# JSON output
rma search "config" -o json
```

### stats

Show index and analysis statistics.

```bash
rma stats [OPTIONS]
```

**Options:**
```
-o, --output <FORMAT>   Output format [default: text]
                        Values: text, json
```

**Examples:**
```bash
# Show statistics
rma stats

# JSON format
rma stats -o json
```

### init

Initialize RMA configuration in the current directory.

```bash
rma init [OPTIONS]
```

**Options:**
```
    --force     Overwrite existing configuration
```

**Examples:**
```bash
# Initialize config
rma init

# Overwrite existing
rma init --force
```

This creates `.rma/config.json` with default settings.

### daemon

Start the HTTP API server for IDE integration.

```bash
rma daemon [OPTIONS]
```

**Options:**
```
-H, --host <HOST>   Host to bind to [default: 127.0.0.1]
-p, --port <PORT>   Port to listen on [default: 9876]
```

**Examples:**
```bash
# Start with defaults
rma daemon

# Custom host and port
rma daemon -H 0.0.0.0 -p 8080
```

### plugin

Manage WASM analysis plugins.

```bash
rma plugin <ACTION> [OPTIONS]
```

**Actions:**

#### list
List installed plugins.
```bash
rma plugin list
```

#### install
Install a plugin from a WASM file.
```bash
rma plugin install <SOURCE>
```

#### remove
Remove an installed plugin.
```bash
rma plugin remove <NAME>
```

#### test
Test a plugin with a file.
```bash
rma plugin test <PLUGIN> [--file <PATH>]
```

#### info
Show detailed plugin information.
```bash
rma plugin info <NAME>
```

**Examples:**
```bash
# List plugins
rma plugin list

# Install plugin
rma plugin install ./my-rules.wasm

# Test plugin
rma plugin test my-rules --file src/main.rs

# Remove plugin
rma plugin remove my-rules
```

### config

View and modify configuration.

```bash
rma config <ACTION> [OPTIONS]
```

**Actions:**

#### show
Display current configuration.
```bash
rma config show
```

#### get
Get a specific configuration value.
```bash
rma config get <KEY>
```

#### set
Set a configuration value.
```bash
rma config set <KEY> <VALUE>
```

#### path
Show configuration file path.
```bash
rma config path
```

**Examples:**
```bash
# Show all config
rma config show

# Get specific value
rma config get min_severity

# Set value
rma config set min_severity warning

# Show config path
rma config path
```

### completions

Generate shell completion scripts.

```bash
rma completions <SHELL>
```

**Arguments:**
- `SHELL` - Shell to generate completions for
  - Values: bash, zsh, fish, powershell, elvish

**Examples:**
```bash
# Generate and install
rma completions bash > ~/.local/share/bash-completion/completions/rma
rma completions zsh > ~/.zfunc/_rma
rma completions fish > ~/.config/fish/completions/rma.fish
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RMA_CONFIG` | Path to configuration file | `.rma/config.json` |
| `RMA_LOG` | Log level | `info` |
| `RMA_NO_COLOR` | Disable colors | (unset) |
| `OPENAI_API_KEY` | API key for AI analysis | (required for --ai) |
| `RMA_CACHE_DIR` | Cache directory | `~/.cache/rma` |

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Configuration error |
| 4 | Scan found critical issues |
| 5 | IO error |

## Tips

### CI/CD Integration

```yaml
# GitHub Actions
- name: Run RMA
  run: |
    curl -fsSL https://raw.githubusercontent.com/bumahkib7/rust-monorepo-analyzer/master/install.sh | bash
    rma scan . --output sarif -f results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Verbose Debugging

```bash
RMA_LOG=debug rma scan . -vvv
```

### Performance Tuning

```bash
# Use all CPU cores
rma scan . -j 0

# Limit parallelism on memory-constrained systems
rma scan . -j 2
```
