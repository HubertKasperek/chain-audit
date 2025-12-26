# chain-audit

[![CI](https://github.com/hukasx0/chain-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/hukasx0/chain-audit/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/chain-audit.svg)](https://www.npmjs.com/package/chain-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/chain-audit.svg)](https://nodejs.org)

**Fast, zero-dependency CLI to detect supply chain attacks in `node_modules`.**

📖 **[Documentation](https://github.com/hukasx0/chain-audit)** • 🐛 **[Report Bug](https://github.com/hukasx0/chain-audit/issues)** • 💡 **[Request Feature](https://github.com/hukasx0/chain-audit/issues)** • 📦 **[npm package](https://www.npmjs.com/package/chain-audit)**

> ⚠️ Supply chain attacks are on the rise. Incidents like [event-stream](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident), [ua-parser-js](https://github.com/advisories/GHSA-pjwm-rvh2-c87w), [node-ipc](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/), and [Shai-Hulud 2.0](https://www.wiz.io/blog/shai-hulud-2-0-aftermath-ongoing-supply-chain-attack) (November 2025 – compromised PostHog, Postman, AsyncAPI and leaked thousands of secrets) have shown that even popular packages can be compromised. **`npm audit` only detects known CVEs** – it won't catch a malicious postinstall script added yesterday.

**chain-audit** fills this gap by scanning for suspicious patterns that indicate an active attack, not just known vulnerabilities.

---

Scans your installed dependencies for malicious patterns including:
- 🔴 Extraneous packages not in lockfile
- 🔴 Version mismatches vs lockfile
- 🔴 Malicious install scripts (preinstall, postinstall, etc.)
- 🔴 Network access patterns (curl, wget, fetch, Node.js http/https)
- 🔴 Typosquatting attempts
- 🔴 Obfuscated code (base64, hex encoding)
- 🔴 Credential/secret stealing patterns (env vars + network)
- 🟡 Native binary modules
- 🟡 Dynamic code execution (eval, Function, child_process)

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
| SARIF output (GitHub integration) | ✅ | ❌ |

**Use both together** – `npm audit` for known vulnerabilities, `chain-audit` for detecting novel attacks.

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
# Scan current project
chain-audit

# Fail CI on high severity issues
chain-audit --fail-on high

# Show only critical and high severity issues
chain-audit --severity critical,high

# Combine severity filter with fail-on
chain-audit --severity critical,high --fail-on high

# JSON output for processing
chain-audit --json

# SARIF output for GitHub Code Scanning
chain-audit --sarif > results.sarif

# Deep code analysis (slower but more thorough)
chain-audit --scan-code

# Detailed analysis with code snippets and evidence
chain-audit --verbose --scan-code

# Verbose output as JSON for further processing
chain-audit --verbose --json --scan-code
```

## CLI Options

| Option | Description |
|--------|-------------|
| `-n, --node-modules <path>` | Path to node_modules (default: `./node_modules`) |
| `-l, --lock <path>` | Path to lockfile (auto-detects npm, yarn, pnpm, bun) |
| `-c, --config <path>` | Path to config file (auto-detects if not specified) |
| `--json` | Output as JSON |
| `--sarif` | Output as SARIF (for GitHub Code Scanning) |
| `-s, --severity <levels>` | Show only specified severity levels (comma-separated, e.g., `critical,high`) |
| `--fail-on <level>` | Exit 1 if max severity >= level |
| `--scan-code` | Deep scan JS files for suspicious patterns |
| `-V, --verbose` | Show detailed analysis: code snippets with line numbers, matched patterns, package metadata, trust assessment, false positive hints, and verification steps |
| `-q, --quiet` | Suppress warnings |
| `-v, --version` | Print version |
| `-h, --help` | Show help |

## Severity Levels

| Level | Description | Example |
|-------|-------------|---------|
| `critical` | Highly likely malicious | Obfuscated code with network access, extraneous packages |
| `high` | Strong attack indicators | Suspicious install scripts with network/exec, typosquatting |
| `medium` | Warrants investigation | Install scripts, shell execution patterns |
| `low` | Informational | Native binaries, minimal metadata |
| `info` | Metadata only | Trusted packages with install scripts |

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

Issues will be displayed in the order they are found, grouped by the severity levels you specified.

## Example Output

```
chain-audit v0.5.0
────────────────────────────────────────────────────────────

node_modules: /path/to/project/node_modules
lockfile: /path/to/project/package-lock.json
lockfile type: npm-v2
packages scanned: 847

Found 3 potential issue(s):

── CRITICAL ──
  ● evil-package@1.0.0
    reason: extraneous_package
    detail: Package exists in node_modules but is missing from lockfile
    fix: Run `npm ci` to reinstall from lockfile

── HIGH ──
  ● suspic-lib@2.0.0
    reason: network_access_script
    detail: Script "postinstall" contains network access pattern: curl https://...
    fix: Verify that network access is legitimate

── MEDIUM ──
  ● some-addon@1.2.3
    reason: install_script
    detail: Has postinstall script: node-gyp rebuild
    fix: Review the script to ensure it performs only expected operations

────────────────────────────────────────────────────────────
Summary:
  info: 0 │ low: 0 │ medium: 1 │ high: 1 │ critical: 1

Max severity: CRITICAL
```

## Verbose Mode (`--verbose`)

The `--verbose` (`-V`) option provides detailed analysis to investigate findings and distinguish false positives from real threats.

### What's Included

When `--verbose` is enabled, each finding includes:

- **Code snippets** with line numbers showing exactly where issues were detected (3 lines of context before/after)
- **Matched patterns** (regex) that triggered the detection
- **Package metadata**: author, repository URL, license, homepage, full file path
- **Trust assessment**: trust score (0-100) and trust level (low/medium/high)
- **Evidence**: file paths, line numbers, column numbers, matched text
- **False positive hints**: guidance on legitimate uses that might trigger the detection
- **Verification steps**: actionable steps for manual investigation
- **Risk assessment**: for critical findings, notes about known attack patterns (e.g., Shai-Hulud 2.0)

### Trust Score Calculation

The trust score (0-100) is calculated based on multiple factors:

| Factor | Points | Description |
|--------|--------|-------------|
| **Trusted scope** | +40 | Package is from a known trusted scope (e.g., `@babel/*`, `@types/*`, `@eslint/*`) |
| **Known legitimate** | +50 | Package is in the known legitimate packages list |
| **Has repository** | +20 | Package has a repository URL in package.json |
| **Has homepage** | +10 | Package has a homepage URL |
| **Has author** | +10 | Package has author information |
| **Has license** | +10 | Package has a license field |

**Trust Levels:**
- **High (70-100)**: Package is likely legitimate (e.g., from trusted scope with repository)
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

### When to Use Verbose Mode

- **Manual investigation** of suspicious findings
- **Creating security reports** with detailed evidence
- **Debugging false positives** by understanding what triggered the detection
- **Incident response** when you need detailed evidence for documentation
- **Code review** when you need to see exact code snippets and line numbers

## Configuration

Create a config file in your project root. Supported filenames (in priority order):
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
    "esbuild",
    "@swc/*",
    "sharp"
  ],
  "trustedPatterns": {
    "node-gyp rebuild": true,
    "prebuild-install": true
  },
  "scanCode": false,
  "failOn": "high",
  "severity": ["critical", "high"],
  "format": "text",
  "verbose": false,
  "quiet": false,
  "maxFileSizeForCodeScan": 1048576,
  "maxNestedDepth": 10
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ignoredPackages` | `string[]` | `[]` | Packages to skip (supports `*` wildcards) |
| `ignoredRules` | `string[]` | `[]` | Rule IDs to ignore |
| `trustedPackages` | `string[]` | `[esbuild, sharp, ...]` | Packages with reduced severity for install scripts |
| `trustedPatterns` | `object` | `{node-gyp rebuild: true, ...}` | Install script patterns considered safe |
| `scanCode` | `boolean` | `false` | Enable deep code scanning by default |
| `failOn` | `string` | `null` | Default fail threshold (`info\|low\|medium\|high\|critical`) |
| `severity` | `string[]` | `null` | Show only specified severity levels (e.g., `["critical", "high"]`) |
| `format` | `string` | `"text"` | Output format: `text`, `json`, or `sarif` |
| `verbose` | `boolean` | `false` | Show detailed analysis with code snippets and trust scores |
| `quiet` | `boolean` | `false` | Suppress warnings |
| `maxFileSizeForCodeScan` | `number` | `1048576` | Max file size (bytes) to scan for code patterns |
| `maxNestedDepth` | `number` | `10` | Max depth to traverse nested node_modules |

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

### With SARIF Upload (GitHub Code Scanning)

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
- `fail-on` (default: `high`) – Severity threshold to fail on (info|low|medium|high|critical)
- `scan-code` (default: `false`) – Enable deep code scanning (slower)
- `upload-sarif` (default: `true`) – Upload SARIF to GitHub Code Scanning

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

### ⚠️ CI/CD Security Best Practices

Supply chain attacks like [Shai-Hulud 2.0](https://www.wiz.io/blog/shai-hulud-2-0-aftermath-ongoing-supply-chain-attack) exploited misconfigured GitHub Actions. **Protect your CI/CD:**

```yaml
# ❌ DANGEROUS - Don't use pull_request_target with checkout
on: pull_request_target  # Gives write access + secrets to fork PRs!

# ✅ SAFE - Use pull_request (no secrets exposed to forks)
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
| `package-lock.json` | npm v2/v3 |
| `npm-shrinkwrap.json` | npm |
| `yarn.lock` | Yarn Classic & Berry |
| `pnpm-lock.yaml` | pnpm |
| `bun.lock` | Bun |

## Detection Rules

### Critical Severity
- **extraneous_package** – Package in node_modules not in lockfile
- **version_mismatch** – Installed version differs from lockfile
- **pipe_to_shell** – Script pipes content to shell (`| bash`)
- **potential_env_exfiltration** – Env access + network in install script
- **env_with_network** – Code accesses env vars and has network/exec capabilities
- **obfuscated_code** – Base64/hex encoded strings, char code arrays

### High Severity
- **network_access_script** – Install script with curl/wget/fetch patterns
- **potential_typosquat** – Package name similar to popular package
- **suspicious_name_pattern** – Package name uses character substitution (l33t speak)
- **eval_usage** – Code uses eval() or new Function()
- **sensitive_path_access** – Code accesses ~/.ssh, ~/.aws, etc.
- **shell_execution** – Script executes shell commands

### Medium Severity
- **install_script** – Has preinstall/install/postinstall/prepare script
- **code_execution** – Script runs code via node -e, python -c, etc.
- **child_process_usage** – Code uses child_process module
- **node_network_access** – Code uses Node.js network APIs (fetch, https, axios)
- **git_operation_install** – Install script performs git operations

### Low/Info Severity
- **native_binary** – Contains .node, .so, .dll, .dylib files
- **no_repository** – No repository URL in package.json
- **minimal_metadata** – Very short/missing description

## Programmatic Usage

```javascript
const { run } = require('chain-audit');

const result = await run(['node', 'script.js', '--json', '--fail-on', 'high']);

console.log(result.exitCode);  // 0 or 1
console.log(result.issues);    // Array of issues found
console.log(result.summary);   // { counts: {...}, maxSeverity: 'high' }
```

## Best Practices

### ⚠️ Important: When to Run chain-audit

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

> ⚠️ **Warning:** Even with `--ignore-scripts`, there is no 100% guarantee of security. Malicious code could execute when the package is `require()`d, or exploit vulnerabilities during extraction. For maximum security:
> - Run installation in a **sandboxed environment**: Docker, Podman, or a VM (VirtualBox, VMware, QEMU/KVM)
> - Use ephemeral CI runners (GitHub Actions, GitLab CI) that are destroyed after each run
> - Never install untrusted packages on production or development machines directly

### General Guidelines

1. **Always use lockfiles** – Run `npm ci` instead of `npm install` in CI
2. **Use `--ignore-scripts` + chain-audit + rebuild** – Scan before scripts execute
3. **Run in sandboxed CI** – Isolate potentially malicious code
4. **Combine with npm audit** – chain-audit detects different threats
5. **Review all findings** – Some may be false positives
6. **Use `--scan-code` periodically** – More thorough but slower
7. **Use `--verbose` for manual investigation** – Get code snippets and trust assessment to distinguish false positives
8. **Keep registry secure** – Use private registry or npm audit signatures

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

**⚠️ Disclaimer:** chain-audit is a heuristic scanner created for **educational and research purposes**, provided "AS IS" without warranty of any kind. It may produce false positives and **cannot catch all attacks**. Even with `--ignore-scripts`, malicious packages could execute code on `require()` etc. 

**The author(s) take no responsibility for:**
- False positives or false negatives in detection
- Missed malicious packages or vulnerabilities
- Any damages resulting from use or inability to use this tool
- Security incidents that occur despite using this tool
- and more

**By using chain-audit, you accept full responsibility for your actions and security decisions.**

**Always:**
- Install dependencies in isolated environments (Docker, VirtualBox, VMware, QEMU/KVM)
- Review findings manually  
- Use as part of a defense-in-depth security strategy
- Never trust any single tool as your only line of defense
