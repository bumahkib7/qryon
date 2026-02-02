# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.14.x  | :white_check_mark: |
| 0.13.x  | :white_check_mark: |
| < 0.13  | :x:                |

## Reporting a Vulnerability

We take the security of RMA seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Use GitHub's private vulnerability reporting:
   - Go to [Security Advisories](https://github.com/bumahkib7/rust-monorepo-analyzer/security/advisories/new)
   - Click "Report a vulnerability"
   - Fill out the form with details

### What to Include

- Type of vulnerability (RCE, path traversal, DoS, etc.)
- Full path to the vulnerable code (if known)
- Step-by-step instructions to reproduce
- Proof of concept (if possible)
- Impact assessment
- Suggested fix (if you have one)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release

### What to Expect

1. Acknowledgment of your report
2. Assessment of the vulnerability
3. Development of a fix
4. Coordinated disclosure (we'll credit you unless you prefer anonymity)
5. Security advisory publication

## Security Best Practices for RMA Users

### Running RMA Safely

1. **Sandboxing**: Run RMA in a sandboxed environment when analyzing untrusted code
2. **Permissions**: RMA only needs read access to source files
3. **CI/CD**: Use the official GitHub Action with minimal permissions
4. **Updates**: Keep RMA updated to receive security fixes

### Secure Configuration

```toml
# rma.toml - Recommended security settings
[security]
# Exclude sensitive directories from analysis
exclude = ["**/secrets/**", "**/.env*", "**/credentials/**"]

# Don't follow symlinks (prevents path traversal)
follow_symlinks = false
```

## Security Features

RMA includes several security features:

- **No Code Execution**: RMA only parses and analyzes code statically
- **No Network Access**: Core analysis is fully offline
- **Path Validation**: Prevents path traversal in file operations
- **Memory Safety**: Written in Rust with no unsafe code in critical paths

## Acknowledgments

We thank the following individuals for responsibly disclosing security issues:

<!-- List will be updated as reports are received -->

*No reports yet*

---

Thank you for helping keep RMA and its users safe!
