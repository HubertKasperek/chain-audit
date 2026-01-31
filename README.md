# chain-audit

[![CI](https://github.com/hukasx0/chain-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/hukasx0/chain-audit/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/chain-audit.svg)](https://www.npmjs.com/package/chain-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/chain-audit.svg)](https://nodejs.org)

**Zero-dependency heuristic scanner CLI to detect supply chain attacks in `node_modules`.**

> **Disclaimer:** chain-audit is a **heuristic scanner** that searches for suspicious patterns in code. It does **not** detect 100% confirmed attacks, but rather flags potentially suspicious behavior that requires **human analysis**. The tool may produce **false positives** (flagging legitimate code as suspicious) and **false negatives** (missing real attacks). It's up to you to review and determine whether findings are actually suspicious or legitimate. Always investigate findings before taking action.  
> Licensed under **MIT License**, provided "AS IS" without warranty of any kind.

---

## Why chain-audit?

| Feature | chain-audit | npm audit |
|---------|-------------|-----------|
| Detects known CVEs | ❌ | ✅ |
| Detects malicious install scripts | ✅ | ❌ |
| Detects typosquatting | ✅ | ❌ |
| Detects extraneous packages | ✅ | ❌ |
| Detects obfuscated code | ✅ | ❌ |
| Zero dependencies | ✅ | N/A |
| Works offline | ✅ | ❌ |
| SARIF output (GitHub integration) [experimental] | ✅ | ❌ |

**Use both together** – `npm audit` for known vulnerabilities, `chain-audit` (heuristic scanner) for detecting novel attacks and suspicious patterns.

## Installation

```bash
# Global install
npm install -g chain-audit

# Or use directly with npx
npx chain-audit

# Or as dev dependency
npm install -D chain-audit

# Or with bun
bun add -d chain-audit
```

### Single Executable (Standalone Binary)

> **Note:** In 99.99% of cases, `npm install -g chain-audit` is sufficient. Standalone executables are only for special cases where Node.js, npm, Bun, or other package managers are unavailable or installation is restricted.

Pre-built standalone executables are available in the [GitHub Releases](https://github.com/hukasx0/chain-audit/releases) for Linux (x64 and ARM64). These are self-contained binaries that don't require Node.js or Bun to be installed.

**Use cases for standalone executables:**
- CI/CD environments without Node.js
- Air-gapped systems
- Systems with restricted installation permissions
- Distribution to teams without package managers

You can also compile chain-audit to a standalone binary yourself (For Linux, Windows and MacOS) using Bun:

```bash
# Clone the repository
git clone https://github.com/hukasx0/chain-audit.git
cd chain-audit

# Compile to single executable
bun build src/index.js --compile --outfile chain-audit

# Now you have a standalone binary
./chain-audit --help
```

## Quick Start

```bash
# Recommended: Thorough scan with detailed analysis
chain-audit --scan-code --detailed

# Scan current project (basic scan)
chain-audit

# Fail CI on high severity issues
chain-audit --fail-on high

# Show only critical and high severity issues
chain-audit --severity critical,high

# Combine severity filter with fail-on
chain-audit --severity critical,high --fail-on high

# JSON output for processing
chain-audit --json

# SARIF output for GitHub Code Scanning (experimental)
chain-audit --sarif > results.sarif

# Deep code analysis (slower but more thorough)
chain-audit --scan-code

# Detailed analysis with code snippets and evidence
chain-audit --detailed --scan-code

# Detailed output as JSON for further processing
chain-audit --detailed --json --scan-code

# Ignore specific packages and rules
chain-audit --ignore-packages "@types/*" --ignore-rules native_binary,executable_files

# Additional structure integrity checks
chain-audit --verify-integrity --fail-on high

# Deep scan with no file limit
chain-audit --scan-code --max-files 0 --detailed

# Custom scan limits
chain-audit --max-file-size 2097152 --max-depth 15

# Enable typosquatting detection (disabled by default)
chain-audit --check-typosquatting
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-n, --node-modules <path>` | Path to node_modules (default: `./node_modules`) |
| `-l, --lock <path>` | Path to lockfile (auto-detects npm, yarn, pnpm, bun) |
| `-c, --config <path>` | Path to config file (auto-detects if not specified) |
| `--json` | Output as JSON |
| `--sarif` | Output as SARIF (for GitHub Code Scanning) [experimental] |
| `-s, --severity <levels>` | Show only specified severity levels (comma-separated, e.g., `critical,high`) |
| `--fail-on <level>` | Exit 1 if max severity >= level |
| `--scan-code` | Deep scan JS files for suspicious patterns |
| `-V, --detailed` | Show detailed analysis: code snippets with line numbers, matched patterns, package metadata, trust assessment, false positive hints, and verification steps (`--verbose` is an alias for backward compatibility) |
| `-v, --version` | Print version |
| `-h, --help` | Show help |
| `--init` | Generate example config file (`.chainauditrc.json`) |
| `-f, --force` | Force overwrite existing config file (use with `--init`) |
| **Filtering Options** | |
| `-I, --ignore-packages <list>` | Ignore packages (comma-separated, supports globs, e.g., `@types/*,lodash`) |
| `-R, --ignore-rules <list>` | Ignore rule IDs (comma-separated, e.g., `native_binary,executable_files,install_script`) |
| `-T, --trust-packages <list>` | Trust packages (comma-separated, supports globs, e.g., `esbuild,@swc/*`) |
| **Scan Options** | |
| `--max-file-size <bytes>` | Max file size to scan (default: 1048576 = 1MB) |
| `--max-depth <n>` | Max nested node_modules depth (default: 10) |
| `--max-files <n>` | Max JS files to scan per package (0 = unlimited, default: 0) |
| `--verify-integrity` | Additional checks for package structure tampering |
| `--check-typosquatting` | Enable typosquatting detection (disabled by default) |
| `--check-lockfile` | Check lockfile integrity (disabled by default due to possible false positives) |

## Severity Levels

| Level | Description | Example |
|-------|-------------|---------|
| `critical` | Highly likely malicious | Obfuscated code with network access, version mismatch |
| `high` | Strong attack indicators | Suspicious install scripts with network/exec, typosquatting |
| `medium` | Warrants investigation | Install scripts, shell execution patterns |
| `low` | Informational | Native binaries, minimal metadata |
| `info` | Metadata only | Packages with install scripts that are in trusted packages list (if configured) |

### Filtering by Severity

Use `--severity` to show only specific severity levels. You can specify multiple levels separated by commas:

```bash
# Show only critical issues
chain-audit --severity critical

# Show critical and high issues
chain-audit --severity critical,high

# Show low and medium issues
chain-audit --severity low,medium

# Combine with --fail-on for CI pipelines
chain-audit --severity critical,high --fail-on high
```

Issues will be displayed sorted by severity (highest first), then by package name, grouped by severity level. When using `--severity`, only the specified severity levels are shown.

## Example Output

```
chain-audit v0.6.3
Zero-dependency heuristic scanner CLI to detect supply chain attacks in node_modules
────────────────────────────────────────────────────────────

node_modules: /path/to/project/node_modules
lockfile: /path/to/project/package-lock.json
lockfile type: npm-v2
packages scanned: 847

Found 3 potential issue(s):

── CRITICAL ──
  ● evil-package@1.0.0
    reason: version_mismatch
    detail: Installed version 1.0.0 does not match lockfile version 0.9.5
    fix: Run `npm ci` to reinstall correct version

── HIGH ──
  ● suspic-lib@2.0.0
    reason: network_access_script
    detail: Script "postinstall" contains network access pattern: curl https://...
    fix: Verify that network access is legitimate

── MEDIUM ──
  ● some-addon@1.2.3
    reason: extraneous_package
    detail: Package exists in node_modules but is missing from lockfile
    fix: Run `npm ci` to reinstall from lockfile

────────────────────────────────────────────────────────────
Summary:
  info: 0 │ low: 0 │ medium: 1 │ high: 1 │ critical: 1

Max severity: CRITICAL
```

## Detailed Mode (`--detailed`)

The `--detailed` (`-V`) option provides detailed analysis to investigate findings and distinguish false positives from real threats.

> **Note:** `--verbose` is an alias for `--detailed` and is supported for backward compatibility.

### What's Included

When `--detailed` is enabled, each finding includes:

- **Code snippets** with line numbers showing exactly where issues were detected (3 lines of context before/after)
- **Matched patterns** (regex) that triggered the detection
- **Package metadata**: author, repository URL, license, homepage, full file path
- **Trust assessment**: trust score (0-100) and trust level (low/medium/high)
- **Evidence**: file paths, line numbers, column numbers (in matches array), matched text
- **False positive hints**: guidance on legitimate uses that might trigger the detection
- **Verification steps**: actionable steps for manual investigation (available for some findings like typosquatting)
- **Risk assessment**: for high/critical findings, notes about known attack patterns

### Trust Score Calculation

The trust score (0-100) is calculated based on multiple factors:

| Factor | Points | Description |
|--------|--------|-------------|
| **Trusted scope** | +40 | Package is from a scope in the internal trusted scopes list (currently empty by default) |
| **Known legitimate** | +50 | Package is in the internal known legitimate packages list (currently empty by default) |
| **Has repository** | +20 | Package has a repository URL in package.json |
| **Has homepage** | +10 | Package has a homepage URL |
| **Has author** | +10 | Package has author information |
| **Has license** | +10 | Package has a license field |

**Note:** Trust score is calculated independently from the `trustedPackages` config option. The `trustedPackages` config option affects severity levels for install scripts, but does not influence the trust score calculation. By default, no packages are whitelisted in the trust score calculation. All packages are checked with equal severity.

**Trust Levels:**
- **High (70-100)**: Package is likely legitimate (e.g., has repository, homepage, author, and license)
- **Medium (40-69)**: Package has some trust indicators but needs verification
- **Low (0-39)**: Package lacks trust indicators, warrants closer investigation

**Example:**
```
Trust Assessment:
  trust score: 40/100 (medium)
  ✓ Has homepage
  ✓ Has author
  ✓ Has license
  ✗ Not from trusted scope
  ✗ No repository
```

### When to Use Detailed Mode

- **Manual investigation** of suspicious findings
- **Creating security reports** with detailed evidence
- **Debugging false positives** by understanding what triggered the detection
- **Incident response** when you need detailed evidence for documentation
- **Code review** when you need to see exact code snippets and line numbers

## Configuration

### Initializing a Config File

The easiest way to create a configuration file is to use the `--init` flag:

```bash
# Generate example config file (.chainauditrc.json)
chain-audit --init

# Overwrite existing config file
chain-audit --init --force
```

This will create a `.chainauditrc.json` file in your project root with all available configuration options and example values.

### Manual Configuration

Alternatively, you can manually create a config file in your project root. Supported filenames (in priority order):
- `.chainauditrc.json`
- `.chainauditrc`
- `chainaudit.config.json`

```json
{
  "ignoredPackages": [
    "@types/*",
    "my-internal-*"
  ],
  "ignoredRules": [
    "native_binary"
  ],
  "trustedPackages": [
    // Empty by default - all packages are checked without exceptions
    // Add packages here only if you need to reduce false positives for specific packages
    // Example: "esbuild", "@swc/*", "sharp"
  ],
  "trustedPatterns": {
    "node-gyp rebuild": true,
    "prebuild-install": true,
    "node-pre-gyp": true
  },
  "scanCode": false,
  "checkTyposquatting": false,
  "checkLockfile": false,
  "failOn": "high",
  "severity": ["critical", "high"],
  "format": "text",
  "verbose": false,
  "maxFileSizeForCodeScan": 1048576,
  "maxNestedDepth": 10,
  "maxFilesPerPackage": 0,
  "verifyIntegrity": false
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ignoredPackages` | `string[]` | `[]` | Packages to skip (supports `*` wildcards) |
| `ignoredRules` | `string[]` | `[]` | Rule IDs to ignore |
| `trustedPackages` | `string[]` | `[]` | Packages with reduced severity for install scripts (empty by default - all packages are checked) |
| `trustedPatterns` | `object` | `{node-gyp rebuild: true, ...}` | Install script patterns considered safe |
| `scanCode` | `boolean` | `false` | Enable deep code scanning by default |
| `checkTyposquatting` | `boolean` | `false` | Enable typosquatting detection (disabled by default to reduce false positives) |
| `checkLockfile` | `boolean` | `false` | Enable lockfile integrity checks (disabled by default due to possible false positives) |
| `failOn` | `string` | `null` | Default fail threshold (`info\|low\|medium\|high\|critical`) |
| `severity` | `string[]` | `null` | Show only specified severity levels (e.g., `["critical", "high"]`) |
| `format` | `string` | `"text"` | Output format: `text`, `json`, or `sarif` (sarif is experimental) |
| `verbose` | `boolean` | `false` | Show detailed analysis with code snippets and trust scores (Note: CLI flag is `--detailed`, but config uses `verbose` for consistency) |
| `maxFileSizeForCodeScan` | `number` | `1048576` | Max file size (bytes) to scan for code patterns |
| `maxNestedDepth` | `number` | `10` | Max depth to traverse nested node_modules |
| `maxFilesPerPackage` | `number` | `0` | Max JS files to scan per package (0 = unlimited) |
| `verifyIntegrity` | `boolean` | `false` | Enable additional package structure integrity checks |

## GitHub Actions Integration

### Basic Usage (Safe Mode)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  supply-chain-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      # Install WITHOUT running postinstall scripts (safe)
      - name: Install dependencies (no scripts)
        run: npm ci --ignore-scripts
      
      # Scan BEFORE any install scripts execute
      - name: Run chain-audit
        run: npx chain-audit --fail-on high
      
      # Only rebuild if scan passes
      - name: Run install scripts
        run: npm rebuild
```

### With SARIF Upload (GitHub Code Scanning) [experimental]

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  supply-chain-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Install dependencies (no scripts)
        run: npm ci --ignore-scripts
      
      - name: Run chain-audit
        run: npx chain-audit --sarif > chain-audit.sarif
        continue-on-error: true
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: chain-audit.sarif
          category: supply-chain
      
      - name: Run install scripts
        run: npm rebuild
```

### Using Reusable Workflow (Experimental)

Instead of copying workflow code, use the reusable workflow from this repository:

```yaml
name: Supply Chain Scan
on: [push, pull_request]

jobs:
  scan:
    uses: hukasx0/chain-audit/.github/workflows/scan.yml@main
    with:
      fail-on: high
      scan-code: false
      upload-sarif: true
```

**Available inputs:**
- `node-modules-path` (default: `./node_modules`) – Path to node_modules directory
- `fail-on` (default: `critical`) – Severity threshold to fail on (info|low|medium|high|critical)
- `scan-code` (default: `false`) – Enable deep code scanning (slower)
- `upload-sarif` (default: `true`) – Upload SARIF to GitHub Code Scanning [experimental]

The reusable workflow automatically uses `--ignore-scripts` for safe installation.

### Monorepo Example

```yaml
- name: Scan all workspaces
  run: |
    for pkg in packages/*/; do
      if [ -d "${pkg}node_modules" ]; then
        echo "Scanning $pkg"
        npx chain-audit -n "${pkg}node_modules" --fail-on high
      fi
    done
```

### CI/CD Security Best Practices

Supply chain attacks have exploited misconfigured GitHub Actions. **Protect your CI/CD:**

```yaml
# DANGEROUS - Don't use pull_request_target with checkout
on: pull_request_target  # Gives write access + secrets to fork PRs!

# SAFE - Use pull_request (no secrets exposed to forks)
on: pull_request
```

**Security checklist:**
- [ ] **Never use `pull_request_target`** with `actions/checkout` – it exposes secrets to malicious PRs
- [ ] **Minimize permissions** – use `permissions: read-all` or specific minimal permissions
- [ ] **Don't pass secrets to npm scripts** – malicious postinstall can read `process.env`
- [ ] **Use `--ignore-scripts`** – run chain-audit before `npm rebuild`
- [ ] **Pin action versions** – use `@v4` or SHA, not `@main`
- [ ] **Review workflow changes** – require approval for `.github/workflows` modifications

```yaml
# Example: Minimal permissions
permissions:
  contents: read
  # Only add more if absolutely needed
```

## Lockfile Support

chain-audit automatically detects and parses:

| Lockfile | Package Manager |
|----------|-----------------|
| `package-lock.json` | npm v2/v3 (v1 supported as fallback) |
| `npm-shrinkwrap.json` | npm (v1/v2/v3) |
| `yarn.lock` | Yarn Classic & Berry |
| `pnpm-lock.yaml` | pnpm |
| `bun.lock` | Bun (text format) |
| `bun.lockb` | Bun (binary format, not supported - use `bun install --save-text-lockfile` to generate text format) |

## Detection Rules

### Critical Severity
- **version_mismatch** – Installed version differs from lockfile (requires `--check-lockfile`)
- **pipe_to_shell** – Script pipes content to shell (`| bash`)
- **potential_env_exfiltration** – Env access + network in install script

### High Severity
- **corrupted_package_json** – Package has malformed or unreadable package.json

### High Severity (with `--verify-integrity`)
- **package_name_mismatch** – Package name in package.json doesn't match expected from path
- **suspicious_resolved_url** – Package resolved from local file or suspicious URL

### High Severity
- **network_access_script** – Install script with curl/wget/fetch patterns (high for install scripts, low for trusted install scripts, medium/low for others)
- **potential_typosquat** – Package name similar to popular package (requires `--check-typosquatting`)
- **suspicious_name_pattern** – Package name uses character substitution (l33t speak) or prefix patterns (requires `--check-typosquatting`) (high for character substitution, medium for prefix patterns)
- **eval_usage** – Code uses eval() or new Function() (requires `--scan-code`)
- **sensitive_path_access** – Code accesses ~/.ssh, ~/.aws, etc. (requires `--scan-code`)
- **shell_execution** – Script executes shell commands (high for install scripts, medium/low for others)

### Critical Severity (with `--scan-code`)
- **obfuscated_code** – Base64/hex encoded strings, char code arrays

### High Severity (with `--scan-code`)
- **env_with_network** – Code accesses env vars and has network/exec capabilities (critical severity, or medium for install scripts)

### Medium Severity
- **extraneous_package** – Package in node_modules not in lockfile (requires `--check-lockfile`)
- **install_script** – Has preinstall/install/postinstall script (medium, or info/low for trusted packages/patterns)
- **code_execution** – Script runs code via node -e, python -c, etc. (high for install scripts, medium/low for others)
- **child_process_usage** – Code uses child_process module
- **node_network_access** – Code uses Node.js network APIs (fetch, https, axios)
- **git_operation_install** – Install script performs git operations
- **executable_files** – Contains executable files (shell scripts, etc.) - high if outside bin/, medium if in bin/

### Low/Info Severity
- **native_binary** – Contains native module binaries (.node, .so, .dylib files)
- **no_repository** – No repository URL in package.json
- **minimal_metadata** – Very short/missing description

## Programmatic Usage

```javascript
const { run } = require('chain-audit');

const result = run(['node', 'script.js', '--json', '--fail-on', 'high']);

console.log(result.exitCode);  // 0 or 1
console.log(result.issues);    // Array of all issues found (not filtered by --severity)
console.log(result.summary);   // { counts: {...}, maxSeverity: 'high' } (calculated from filtered issues if --severity is used)

// Note: run() also outputs to console.log() by default. Use --json format to get structured output.
```

## Best Practices

### Important: When to Run chain-audit

**Problem:** If you run chain-audit *after* `npm install`, malicious `postinstall` scripts have already executed – it's too late!

**Solution:** Install without running scripts, scan, then rebuild:

```bash
# 1. Install WITHOUT running lifecycle scripts
npm ci --ignore-scripts

# 2. Scan for malicious packages
npx chain-audit --fail-on high

# 3. If clean, run the install scripts
npm rebuild
```

> 💡 **Note:** chain-audit analyzes scripts by reading them from `package.json` files (static analysis), not by executing them. This means it can detect malicious scripts even when using `--ignore-scripts`, because it reads the script content as text and checks for suspicious patterns

> **Warning:** Even with `--ignore-scripts`, there is no 100% guarantee of security. Malicious code could execute when the package is `require()`d, or exploit vulnerabilities during extraction. For maximum security:
> - Run installation in a **sandboxed environment**: Docker, Podman, or a VM (VirtualBox, VMware, QEMU/KVM)
> - Use ephemeral CI runners (GitHub Actions, GitLab CI) that are destroyed after each run
> - Never install untrusted packages on production or development machines directly

### General Guidelines

1. **Always use lockfiles** – Run `npm ci` instead of `npm install` in CI
2. **Use `--ignore-scripts` + chain-audit + rebuild** – Scan before scripts execute
3. **Run in sandboxed CI** – Isolate potentially malicious code
4. **Combine with npm audit** – chain-audit detects different threats
5. **Review all findings** – Some may be false positives
6. **Recommended: Use `--scan-code --detailed` for thorough analysis** – Deep code scanning with detailed evidence (slower but most comprehensive)
7. **Use `--detailed` for manual investigation** – Get code snippets and trust assessment to distinguish false positives (`--verbose` is an alias)
8. **Keep registry secure** – Use private registry or npm audit signatures
9. **All packages are checked equally** – No packages are whitelisted by default. Even popular packages like `sharp`, `esbuild`, or `@babel/*` are checked for malicious patterns. This ensures that compromised packages are detected regardless of their reputation.

## Contributing

**Repository:** [github.com/hukasx0/chain-audit](https://github.com/hukasx0/chain-audit)

```bash
# Clone and install
git clone https://github.com/hukasx0/chain-audit.git
cd chain-audit
npm install

# Run linter
npm run lint

# Run tests
npm test

# Test on a real project
node src/index.js --node-modules /path/to/project/node_modules
```

## License

Hubert Kasperek

[MIT License](https://github.com/hukasx0/chain-audit/blob/main/LICENSE)

---

**Disclaimer:** chain-audit is a **heuristic scanner** created for **educational and research purposes**, licensed under **MIT License**, provided "AS IS" without warranty of any kind. The author makes no guarantees about the tool's accuracy, completeness, or reliability. 

**Important limitations:**
- chain-audit does **not** detect 100% confirmed attacks – it scans code for suspicious patterns
- It may produce **many false positives** – findings require human analysis to determine if they're actually suspicious
- It **cannot catch all attacks** – sophisticated or novel attack patterns may be missed
- The tool flags potentially suspicious behavior, but **you are responsible** for reviewing and validating all findings

**The author takes no responsibility for:**
- False positives or false negatives in detection
- Missed malicious packages or vulnerabilities
- Any damages resulting from use or inability to use this tool
- Security incidents that occur despite using this tool
- and more

**By using chain-audit, you accept full responsibility for your actions and security decisions.**
