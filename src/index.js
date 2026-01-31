#!/usr/bin/env node
/**
 * chain-audit - Supply chain attack heuristic scanner for node_modules
 * 
 * Detects suspicious patterns in dependencies including:
 * - Malicious install scripts
 * - Code execution patterns (eval, Function, child_process)
 * - Environment variable access
 * - Network requests in scripts
 * - Extraneous/modified packages
 * - Typosquatting attempts
 * - Native binaries
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { parseArgs } = require('./cli');
const { loadConfig, mergeConfig, initConfig } = require('./config');
const { buildLockIndex } = require('./lockfile');
const { collectPackages, safeReadJSONWithDetails } = require('./collector');
const { analyzePackage } = require('./analyzer');
const { formatText, formatJson, formatSarif } = require('./formatters');
const { color, colors } = require('./utils');

const pkgMeta = (safeReadJSONWithDetails(path.join(__dirname, '..', 'package.json')).data) || {};

function detectDefaultLockfile(cwd) {
  const candidates = [
    'package-lock.json',
    'npm-shrinkwrap.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'bun.lock',
  ];
  for (const candidate of candidates) {
    const full = path.resolve(cwd, candidate);
    if (fs.existsSync(full)) return full;
  }
  return null;
}

function summarize(issues) {
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  let maxSeverity = null;
  const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];

  const rankSeverity = (level) => {
    const idx = severityOrder.indexOf(level);
    return idx === -1 ? -1 : idx;
  };

  for (const issue of issues) {
    if (counts[issue.severity] !== undefined) {
      counts[issue.severity] += 1;
    }
    if (maxSeverity === null || rankSeverity(issue.severity) > rankSeverity(maxSeverity)) {
      maxSeverity = issue.severity;
    }
  }

  return { counts, maxSeverity };
}

function run(argv = process.argv) {
  const args = parseArgs(argv);

  if (args.help) {
    printHelp();
    return { exitCode: 0 };
  }

  if (args.showVersion) {
    console.log(pkgMeta.version || 'unknown');
    return { exitCode: 0 };
  }

  if (args.init) {
    const result = initConfig(process.cwd(), { force: args.force });
    if (result.success) {
      console.log(color('✓', colors.green), result.message);
      console.log('\nConfiguration options:');
      console.log(color('  ignoredPackages', colors.cyan), '  - Packages to skip during analysis (supports glob patterns)');
      console.log(color('  ignoredRules', colors.cyan), '     - Rule IDs to ignore (e.g., "native_binary,executable_files")');
      console.log(color('  trustedPackages', colors.cyan), '  - Known legitimate packages with install scripts');
      console.log(color('  trustedPatterns', colors.cyan), '  - Patterns that reduce severity for known use cases');
      console.log(color('  scanCode', colors.cyan), '          - Enable deep JS file scanning (slower)');
      console.log(color('  failOn', colors.cyan), '            - Exit 1 when max severity >= level');
      console.log(color('  severity', colors.cyan), '          - Filter to show only specific severity levels');
      console.log(color('  format', colors.cyan), '            - Output format: text, json, sarif (experimental)');
      console.log(color('  detailed', colors.cyan), '          - Show detailed analysis (verbose is alias)');
      return { exitCode: 0 };
    } else {
      if (result.exists) {
        console.log(color('⚠', colors.yellow), result.message);
      } else {
        console.error(color('✗', colors.red), result.message);
      }
      return { exitCode: result.exists ? 0 : 1 };
    }
  }

  // Load and merge configuration
  const fileConfig = args.configPath 
    ? loadConfig(args.configPath)
    : loadConfig(process.cwd());
  const config = mergeConfig(fileConfig, args);

  // Validate paths
  if (!fs.existsSync(config.nodeModules) || !fs.statSync(config.nodeModules).isDirectory()) {
    throw new Error(`node_modules not found at: ${config.nodeModules}`);
  }

  if (config.lockPath && !fs.existsSync(config.lockPath)) {
    throw new Error(`Lockfile not found at: ${config.lockPath}`);
  }

  if (config.lockPath && fs.statSync(config.lockPath).isDirectory()) {
    throw new Error(`Lockfile path is a directory: ${config.lockPath}`);
  }

  // Resolve lockfile
  const resolvedLock = config.lockPath || detectDefaultLockfile(process.cwd());
  const lockIndex = buildLockIndex(resolvedLock);

  // Collect and analyze packages
  const packages = collectPackages(config.nodeModules, config.maxNestedDepth);
  const issues = [];

  for (const pkg of packages) {
    // Skip ignored packages
    if (config.ignoredPackages.some(pattern => matchPattern(pattern, pkg.name))) {
      continue;
    }

    const pkgIssues = analyzePackage(pkg, lockIndex, config);
    for (const issue of pkgIssues) {
      // Skip ignored rules
      if (config.ignoredRules.includes(issue.reason)) {
        continue;
      }

      issues.push({
        ...issue,
        package: pkg.name,
        version: pkg.version,
        path: pkg.relativePath,
      });
    }
  }

  // Filter issues by severity if --severity flag is set
  let filteredIssues = issues;
  if (config.severityFilter && config.severityFilter.length > 0) {
    const severitySet = new Set(config.severityFilter);
    filteredIssues = issues.filter(issue => severitySet.has(issue.severity));
  }

  const summary = summarize(filteredIssues);
  const context = {
    nodeModules: config.nodeModules,
    lockfile: lockIndex.lockPresent ? resolvedLock : null,
    lockfileType: lockIndex.lockType,
    packageCount: packages.length,
    failLevel: config.failOn,
    severityFilter: config.severityFilter,
    version: pkgMeta.version,
    verbose: config.verbose,
  };

  // Output results
  let output;
  switch (config.format) {
    case 'json':
      output = formatJson(filteredIssues, summary, context);
      break;
    case 'sarif':
      output = formatSarif(filteredIssues, summary, context);
      break;
    default:
      output = formatText(filteredIssues, summary, context);
  }

  console.log(output);

  // Determine exit code
  const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];
  const rankSeverity = (level) => level === null ? -1 : severityOrder.indexOf(level);

  if (config.failOn && summary.maxSeverity !== null && rankSeverity(summary.maxSeverity) >= rankSeverity(config.failOn)) {
    return { exitCode: 1, issues, summary };
  }

  return { exitCode: 0, issues, summary };
}

function matchPattern(pattern, name) {
  if (pattern.includes('*')) {
    const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
    return regex.test(name);
  }
  return pattern === name;
}

function printHelp() {
  const text = `
${color('chain-audit', colors.bold)} - Zero-dependency heuristic scanner CLI to detect supply chain attacks in node_modules

${color('USAGE:', colors.bold)}
  chain-audit [options]
  npx chain-audit [options]

${color('OPTIONS:', colors.bold)}
  -n, --node-modules <path>  Path to node_modules (default: ./node_modules)
  -l, --lock <path>          Path to lockfile (auto-detects package-lock.json,
                             npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock)
  -c, --config <path>        Path to config file (auto-detects .chainauditrc.json,
                             .chainauditrc, chainaudit.config.json)
  --json                     Output as JSON
  --sarif                    Output as SARIF (for GitHub Code Scanning) [experimental]
  -s, --severity <levels>    Show only specified severity levels (comma-separated)
                             e.g., --severity critical,high or --severity low
  --fail-on <level>          Exit 1 when max severity >= level
                             (info|low|medium|high|critical)
  --scan-code                Scan JS files for suspicious patterns (slower)
  --check-typosquatting      Check for typosquatting attempts (disabled by default)
  --check-lockfile           Check lockfile integrity (disabled by default due to false positives)
  -V, --detailed             Show detailed analysis for each finding:
                             • Code snippets with line numbers
                             • Matched patterns and evidence
                             • Package metadata (author, repo, license)
                             • Trust score assessment
                             • False positive analysis hints
                             • Verification steps
                             (--verbose is an alias for backward compatibility)
  -v, --version              Print version
  -h, --help                 Show this help
  --init                     Generate example config file (.chainauditrc.json)
  -f, --force                Force overwrite existing config file (with --init)

${color('FILTERING OPTIONS:', colors.bold)}
  -I, --ignore-packages <list>  Ignore packages (comma-separated, supports globs)
                                e.g., --ignore-packages "@types/*,lodash"
  -R, --ignore-rules <list>     Ignore rule IDs (comma-separated)
                                e.g., --ignore-rules "native_binary,install_script"
  -T, --trust-packages <list>   Trust packages (comma-separated, supports globs)
                                e.g., --trust-packages "esbuild,@swc/*"

${color('SCAN OPTIONS:', colors.bold)}
  --max-file-size <bytes>    Max file size to scan (default: 1048576 = 1MB)
  --max-depth <n>            Max nested node_modules depth (default: 10)
  --max-files <n>            Max JS files to scan per package (0 = unlimited)
  --verify-integrity         Additional checks for package structure tampering
  --check-typosquatting      Enable typosquatting detection (disabled by default)

${color('SEVERITY LEVELS:', colors.bold)}
  critical  Highly likely malicious (e.g., obfuscated code + network access)
  high      Strong indicators (extraneous packages, suspicious scripts)
  medium    Install scripts with suspicious patterns
  low       Native binaries, informational findings
  info      Metadata-only findings

${color('EXAMPLES:', colors.bold)}
  # Basic scan with auto-detected lockfile
  chain-audit

  # CI mode - fail on high severity issues
  chain-audit --json --fail-on high

  # Show only critical and high severity issues
  chain-audit --severity critical,high

  # Ignore specific packages and rules
  chain-audit --ignore-packages "@types/*" --ignore-rules native_binary

  # Verify package integrity hashes
  chain-audit --verify-integrity --fail-on critical

  # Scan specific path with SARIF output for GitHub
  chain-audit -n ./packages/app/node_modules --sarif

  # Full code analysis (slower but more thorough)
  chain-audit --scan-code --fail-on medium

  # Deep scan with no file limit
  chain-audit --scan-code --max-files 0 --detailed

  # Detailed analysis with code snippets and evidence
  chain-audit --detailed --scan-code

${color('CONFIGURATION:', colors.bold)}
  Create a config file in your project root:
  (.chainauditrc.json, .chainauditrc, or chainaudit.config.json)
  {
    "ignoredPackages": ["@types/*"],
    "ignoredRules": ["native_binary"],
    "trustedPackages": ["my-native-addon"],
    "scanCode": false,
    "failOn": "high",
    "verifyIntegrity": false,
    "maxFilesPerPackage": 0
  }

${color('DISCLAIMER:', colors.bold)}
  Licensed under MIT License, provided "AS IS" without warranty.
  The author makes no guarantees and takes no responsibility for false
  positives, false negatives, missed attacks, or any damages resulting
  from use of this tool. Use at your own risk. Always review findings
  manually and use as part of defense-in-depth.

${color('MORE INFO:', colors.bold)}
  https://github.com/hukasx0/chain-audit
`;
  console.log(text);
}

// Main execution
if (require.main === module) {
  try {
    const { exitCode } = run();
    process.exit(exitCode);
  } catch (err) {
    console.error(color(`Error: ${err.message}`, colors.red));
    if (process.env.DEBUG) {
      console.error(err.stack);
    }
    process.exit(1);
  }
}

// Export for programmatic use and testing
module.exports = { run, summarize };
