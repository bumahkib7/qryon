# RMA GitHub Action

Run RMA security scans in your CI/CD pipeline with automatic SARIF upload to GitHub Security tab.

## Features

- Automatic binary installation (Linux x64/ARM64, macOS x64/ARM64)
- SARIF output with GitHub Security tab integration
- Configurable severity thresholds
- AI-powered analysis support
- Incremental scanning
- Job summary with findings count

## Quick Start

### Using the Reusable Workflow

The simplest way to integrate RMA into your CI/CD:

```yaml
name: Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  security-scan:
    uses: bumahkib7/rust-monorepo-analyzer/.github/workflows/rma-scan-reusable.yml@master
    permissions:
      contents: read
      security-events: write
    with:
      path: '.'
      severity: 'warning'
      upload-sarif: true
```

### Using the Composite Action

For more control over the workflow:

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
        id: rma
        uses: bumahkib7/rust-monorepo-analyzer/.github/actions/rma-scan@master
        with:
          path: './src'
          format: 'sarif'
          severity: 'warning'
          upload-sarif: 'true'

      - name: Check findings
        run: |
          echo "Found ${{ steps.rma.outputs.findings-count }} issues"
```

## Inputs

| Input | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `path` | string | No | `.` | Path to scan (relative to repo root) |
| `format` | string | No | `sarif` | Output format: `text`, `json`, `sarif`, `compact`, `markdown` |
| `output-file` | string | No | `rma-results.sarif` | Output file path |
| `severity` | string | No | `warning` | Minimum severity: `info`, `warning`, `error`, `critical` |
| `languages` | string | No | (all) | Comma-separated languages: `rust,python,javascript,typescript,go,java` |
| `ai` | boolean | No | `false` | Enable AI-powered vulnerability analysis |
| `verbose` | boolean | No | `false` | Enable verbose output |
| `incremental` | boolean | No | `false` | Only scan changed files |
| `extra-args` | string | No | | Additional CLI arguments |
| `version` | string | No | `latest` | RMA version (e.g., `v0.1.0`, `latest`) |
| `upload-sarif` | boolean | No | `true` | Upload SARIF to GitHub Security tab |
| `fail-on-findings` | boolean | No | `false` | Fail the action if findings are detected |
| `token` | string | No | `${{ github.token }}` | GitHub token for API access |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the generated SARIF file |
| `findings-count` | Total number of security findings detected |
| `exit-code` | Exit code from RMA scan |

## Examples

### Basic Security Scan

```yaml
- uses: bumahkib7/rust-monorepo-analyzer/.github/actions/rma-scan@master
  with:
    path: '.'
```

### Scan Specific Languages

```yaml
- uses: bumahkib7/rust-monorepo-analyzer/.github/actions/rma-scan@master
  with:
    path: './backend'
    languages: 'rust,python'
    severity: 'error'
```

### AI-Powered Analysis

```yaml
- uses: bumahkib7/rust-monorepo-analyzer/.github/actions/rma-scan@master
  with:
    path: '.'
    ai: 'true'
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### Fail on Critical Findings

```yaml
- uses: bumahkib7/rust-monorepo-analyzer/.github/actions/rma-scan@master
  with:
    path: '.'
    severity: 'critical'
    fail-on-findings: 'true'
```

### JSON Output for Custom Processing

```yaml
- uses: bumahkib7/rust-monorepo-analyzer/.github/actions/rma-scan@master
  id: scan
  with:
    path: '.'
    format: 'json'
    output-file: 'scan-results.json'
    upload-sarif: 'false'

- name: Process results
  run: |
    jq '.findings | length' scan-results.json
```

### Pin to Specific Version

```yaml
- uses: bumahkib7/rust-monorepo-analyzer/.github/actions/rma-scan@master
  with:
    version: 'v0.1.0'
```

### Use on macOS Runner

```yaml
jobs:
  scan:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bumahkib7/rust-monorepo-analyzer/.github/actions/rma-scan@master
```

## Viewing Results

After the action runs:

1. Go to your repository on GitHub
2. Click the **Security** tab
3. Click **Code scanning alerts**
4. View and manage RMA findings

## Permissions

The action requires these permissions:

```yaml
permissions:
  contents: read         # To checkout code
  security-events: write # To upload SARIF
```

## Supported Platforms

| Runner | Architecture | Status |
|--------|-------------|--------|
| `ubuntu-latest` | x86_64 | Supported |
| `ubuntu-latest` | ARM64 | Supported |
| `macos-latest` | x86_64 | Supported |
| `macos-latest` | ARM64 (Apple Silicon) | Supported |
| `windows-latest` | x86_64 | Not yet supported |

## Troubleshooting

### SARIF Upload Fails

Ensure you have the required permissions:

```yaml
permissions:
  security-events: write
```

### Binary Not Found

The action automatically detects your platform. If it fails:

1. Check the action logs for the detected platform
2. Verify the release has binaries for your platform
3. Try pinning to a specific version

### AI Analysis Not Working

Ensure you've set the `OPENAI_API_KEY` secret:

```yaml
env:
  OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## Contributing

Issues and PRs welcome at [rust-monorepo-analyzer](https://github.com/bumahkib7/rust-monorepo-analyzer).
