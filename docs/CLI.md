# CLI Reference

Complete command-line reference for Qryon.

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
qryon scan [PATH] [OPTIONS]
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
qryon scan .

# Scan with AI analysis
qryon scan ./src --ai

# Only critical and error severity
qryon scan . -s error

# JSON output to file
qryon scan . -o json -f results.json

# SARIF for GitHub Code Scanning
qryon scan . -o sarif -f results.sarif

# Only Rust and Python files
qryon scan . -l rust,python

# Incremental scan (only changed files)
qryon scan . -i

# Use 4 parallel workers
qryon scan . -j 4
```

### AI Analysis

When you use `--ai`, Qryon triages static analysis findings with AI rather than scanning raw files. Each security finding is sent to the AI with surrounding code context, and the AI determines whether it's a true positive, false positive, or needs manual review.

**How it works:**
1. Static analysis runs first (as normal)
2. Security findings are extracted with ~30 lines of surrounding code
3. Each finding is sent to the AI for triage (up to 50 findings per scan)
4. AI confirms/rejects each finding and adds explanations
5. High-confidence false positives are automatically removed

**Provider setup:**

| Provider | Env Var | Default Model |
|----------|---------|---------------|
| `claude` (default) | `ANTHROPIC_API_KEY` | claude-sonnet-4-20250514 |
| `openai` | `OPENAI_API_KEY` | gpt-4o |
| `local` | `QRYON_LOCAL_AI_ENDPOINT` | Ollama localhost:11434 |

**Examples:**
```bash
# Triage findings with Claude (default)
export ANTHROPIC_API_KEY=sk-ant-...
qryon scan . --ai

# Use OpenAI
export OPENAI_API_KEY=sk-...
qryon scan . --ai --ai-provider openai

# Use local Ollama (free, private)
qryon scan . --ai --ai-provider local
```

**Configuration in `qryon.toml`:**
```toml
[ai]
enabled = true
provider = "claude"
model = "claude-sonnet-4-20250514"
max_findings = 50
```

CLI arguments override TOML settings. Only security findings are triaged to limit cost.

**Output fields:** When `--ai` is used, findings may include:
- `ai_verdict`: "true_positive", "false_positive", or "needs_review"
- `ai_explanation`: AI's reasoning about the finding
- `ai_confidence`: 0.0-1.0 confidence score

These appear in JSON and SARIF output. High-confidence false positives (>=0.8) are automatically filtered.

### watch

Watch for file changes and re-analyze in real-time.

```bash
qryon watch [PATH] [OPTIONS]
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
qryon watch .

# Watch with screen clear
qryon watch . --clear

# Custom debounce (1 second)
qryon watch . -d 1000

# Only watch Rust files
qryon watch . -l rust
```

### search

Search the index for files, findings, or content.

```bash
qryon search <QUERY> [OPTIONS]
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
qryon search "TODO"

# Search for files by name
qryon search "main.rs" -t file

# Search findings
qryon search "unsafe" -t finding

# Limit results
qryon search "error" -l 10

# JSON output
qryon search "config" -o json
```

### stats

Show index and analysis statistics.

```bash
qryon stats [OPTIONS]
```

**Options:**
```
-o, --output <FORMAT>   Output format [default: text]
                        Values: text, json
```

**Examples:**
```bash
# Show statistics
qryon stats

# JSON format
qryon stats -o json
```

### init

Initialize Qryon configuration in the current directory.

```bash
qryon init [OPTIONS]
```

**Options:**
```
    --force     Overwrite existing configuration
```

**Examples:**
```bash
# Initialize config
qryon init

# Overwrite existing
qryon init --force
```

This creates `.qryon/config.json` with default settings.

### daemon

Start the HTTP API server for IDE integration.

```bash
qryon daemon [OPTIONS]
```

**Options:**
```
-H, --host <HOST>   Host to bind to [default: 127.0.0.1]
-p, --port <PORT>   Port to listen on [default: 9876]
```

**Examples:**
```bash
# Start with defaults
qryon daemon

# Custom host and port
qryon daemon -H 0.0.0.0 -p 8080
```

### plugin

Manage WASM analysis plugins.

```bash
qryon plugin <ACTION> [OPTIONS]
```

**Actions:**

#### list
List installed plugins.
```bash
qryon plugin list
```

#### install
Install a plugin from a WASM file.
```bash
qryon plugin install <SOURCE>
```

#### remove
Remove an installed plugin.
```bash
qryon plugin remove <NAME>
```

#### test
Test a plugin with a file.
```bash
qryon plugin test <PLUGIN> [--file <PATH>]
```

#### info
Show detailed plugin information.
```bash
qryon plugin info <NAME>
```

**Examples:**
```bash
# List plugins
qryon plugin list

# Install plugin
qryon plugin install ./my-rules.wasm

# Test plugin
qryon plugin test my-rules --file src/main.rs

# Remove plugin
qryon plugin remove my-rules
```

### config

View and modify configuration.

```bash
qryon config <ACTION> [OPTIONS]
```

**Actions:**

#### show
Display current configuration.
```bash
qryon config show
```

#### get
Get a specific configuration value.
```bash
qryon config get <KEY>
```

#### set
Set a configuration value.
```bash
qryon config set <KEY> <VALUE>
```

#### path
Show configuration file path.
```bash
qryon config path
```

**Examples:**
```bash
# Show all config
qryon config show

# Get specific value
qryon config get min_severity

# Set value
qryon config set min_severity warning

# Show config path
qryon config path
```

### completions

Generate shell completion scripts.

```bash
qryon completions <SHELL>
```

**Arguments:**
- `SHELL` - Shell to generate completions for
  - Values: bash, zsh, fish, powershell, elvish

**Examples:**
```bash
# Generate and install
qryon completions bash > ~/.local/share/bash-completion/completions/qryon
qryon completions zsh > ~/.zfunc/_qryon
qryon completions fish > ~/.config/fish/completions/qryon.fish
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QRYON_CONFIG` | Path to configuration file | `.qryon/config.json` |
| `QRYON_LOG` | Log level | `info` |
| `QRYON_NO_COLOR` | Disable colors | (unset) |
| `ANTHROPIC_API_KEY` | Anthropic API key for `--ai` with Claude | (required for --ai --ai-provider claude) |
| `OPENAI_API_KEY` | OpenAI API key for `--ai` with OpenAI | (required for --ai --ai-provider openai) |
| `QRYON_LOCAL_AI_ENDPOINT` | Local AI endpoint for `--ai` with Ollama | `http://localhost:11434` |
| `QRYON_CACHE_DIR` | Cache directory | `~/.cache/qryon` |

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
- name: Run Qryon
  run: |
    curl -fsSL https://raw.githubusercontent.com/bumahkib7/qryon/master/install.sh | bash
    qryon scan . --output sarif -f results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Verbose Debugging

```bash
QRYON_LOG=debug qryon scan . -vvv
```

### Performance Tuning

```bash
# Use all CPU cores
qryon scan . -j 0

# Limit parallelism on memory-constrained systems
qryon scan . -j 2
```
