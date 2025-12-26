#!/usr/bin/env node
/**
 * chain-audit - Supply chain attack scanner for node_modules
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
const { loadConfig, mergeConfig } = require('./config');
const { buildLockIndex } = require('./lockfile');
const { collectPackages } = require('./collector');
const { analyzePackage } = require('./analyzer');
const { formatText, formatJson, formatSarif } = require('./formatters');
const { color, colors } = require('./utils');

const pkgMeta = safeReadJSON(path.join(__dirname, '..', 'package.json')) || {};

function safeReadJSON(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

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
  let maxSeverity = 'info';
  const severityOrder = ['info', 'low', 'medium', 'high', 'critical'];

  const rankSeverity = (level) => {
    const idx = severityOrder.indexOf(level);
    return idx === -1 ? -1 : idx;
  };

  for (const issue of issues) {
    if (counts[issue.severity] !== undefined) {
      counts[issue.severity] += 1;
    }
    if (rankSeverity(issue.severity) > rankSeverity(maxSeverity)) {
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
  const packages = collectPackages(config.nodeModules);
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
  const rankSeverity = (level) => severityOrder.indexOf(level);

  if (config.failOn && rankSeverity(summary.maxSeverity) >= rankSeverity(config.failOn)) {
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
${color('chain-audit', colors.bold)} - Supply chain attack scanner for node_modules

${color('USAGE:', colors.bold)}
  chain-audit [options]
  npx chain-audit [options]

${color('OPTIONS:', colors.bold)}
  -n, --node-modules <path>  Path to node_modules (default: ./node_modules)
  -l, --lock <path>          Path to lockfile (auto-detects package-lock.json,
                             npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock)
  -c, --config <path>        Path to config file (.chainauditrc.json)
  --json                     Output as JSON
  --sarif                    Output as SARIF (for GitHub Code Scanning)
  -s, --severity <levels>    Show only specified severity levels (comma-separated)
                             e.g., --severity critical,high or --severity low
  --fail-on <level>          Exit 1 when max severity >= level
                             (info|low|medium|high|critical)
  --scan-code                Scan JS files for suspicious patterns (slower)
  -q, --quiet                Suppress warnings
  -v, --version              Print version
  -h, --help                 Show this help

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

  # Combine severity filter with fail-on
  chain-audit --severity critical,high --fail-on high

  # Scan specific path with SARIF output for GitHub
  chain-audit -n ./packages/app/node_modules --sarif

  # Full code analysis (slower but more thorough)
  chain-audit --scan-code --fail-on medium

${color('CONFIGURATION:', colors.bold)}
  Create .chainauditrc.json in your project root:
  {
    "ignoredPackages": ["@types/*"],
    "ignoredRules": ["native_binary"],
    "scanCode": false,
    "failOn": "high"
  }

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
