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
const os = require('os');
const path = require('path');
const { Worker } = require('worker_threads');
const { parseArgs } = require('./cli');
const { loadConfig, mergeConfig, initConfig } = require('./config');
const { buildLockIndex } = require('./lockfile');
const { collectPackages, safeReadJSONWithDetails } = require('./collector');
const { analyzePackage } = require('./analyzer');
const { formatText, formatJson, formatSarif } = require('./formatters');
const { color, colors, escapeRegExp } = require('./utils');

const pkgMeta = (safeReadJSONWithDetails(path.join(__dirname, '..', 'package.json')).data) || {};

function detectDefaultLockfile(searchStartDirs) {
  const candidates = [
    'package-lock.json',
    'npm-shrinkwrap.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'bun.lock',
  ];

  const starts = Array.isArray(searchStartDirs) ? searchStartDirs : [searchStartDirs];
  const visited = new Set();

  for (const start of starts) {
    if (!start) continue;

    let currentDir = path.resolve(start);
    while (true) {
      if (!visited.has(currentDir)) {
        visited.add(currentDir);
        for (const candidate of candidates) {
          const full = path.join(currentDir, candidate);
          if (fs.existsSync(full) && fs.statSync(full).isFile()) {
            return full;
          }
        }
      }

      const parent = path.dirname(currentDir);
      if (parent === currentDir) break;
      currentDir = parent;
    }
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

function compileGlobMatchers(patterns) {
  const compiled = [];
  const source = Array.isArray(patterns) ? patterns : [];

  for (const pattern of source) {
    if (typeof pattern !== 'string' || pattern.length === 0) {
      continue;
    }

    if (!pattern.includes('*')) {
      compiled.push({ exact: pattern, regex: null });
      continue;
    }

    compiled.push({
      exact: null,
      regex: new RegExp(`^${escapeRegExp(pattern).replace(/\*/g, '.*')}$`),
    });
  }

  return compiled;
}

function matchesAnyCompiledGlob(compiled, value) {
  if (!Array.isArray(compiled) || typeof value !== 'string') {
    return false;
  }

  for (const matcher of compiled) {
    if (matcher.exact !== null) {
      if (matcher.exact === value) {
        return true;
      }
      continue;
    }

    if (matcher.regex && matcher.regex.test(value)) {
      return true;
    }
  }

  return false;
}

function createAnalysisConfig(config) {
  return {
    ...config,
    _trustedPackageMatchers: compileGlobMatchers(config.trustedPackages),
    _trustedPatternKeys: Object.keys(config.trustedPatterns || {}),
  };
}

function flattenAnalyzedIssues(packages, pkgIssuesByIndex, ignoredRules) {
  const ignoredRuleSet = new Set(Array.isArray(ignoredRules) ? ignoredRules : []);
  const issues = [];

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    const pkgIssues = Array.isArray(pkgIssuesByIndex[i]) ? pkgIssuesByIndex[i] : [];

    for (const issue of pkgIssues) {
      if (ignoredRuleSet.has(issue.reason)) {
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

  return issues;
}

function collectIssuesSequential(packages, lockIndex, analysisConfig, ignoredPackageMatchers) {
  const pkgIssuesByIndex = new Array(packages.length);

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];

    if (matchesAnyCompiledGlob(ignoredPackageMatchers, pkg.name)) {
      pkgIssuesByIndex[i] = [];
      continue;
    }

    pkgIssuesByIndex[i] = analyzePackage(pkg, lockIndex, analysisConfig);
  }

  return flattenAnalyzedIssues(packages, pkgIssuesByIndex, analysisConfig.ignoredRules);
}

function serializeLockIndex(lockIndex) {
  return {
    indexByPath: Array.from(lockIndex.indexByPath.entries()),
    indexByName: Array.from(lockIndex.indexByName.entries()),
    lockVersion: lockIndex.lockVersion,
    lockPresent: lockIndex.lockPresent,
    lockType: lockIndex.lockType,
  };
}

function resolveAnalysisJobs(config, packageCount) {
  if (!config.scanCode || packageCount <= 1) {
    return 1;
  }

  const configuredJobs = Number(config.analysisJobs);
  if (Number.isInteger(configuredJobs) && configuredJobs > 0) {
    return Math.max(1, Math.min(configuredJobs, packageCount));
  }

  const available = typeof os.availableParallelism === 'function'
    ? os.availableParallelism()
    : (Array.isArray(os.cpus()) ? os.cpus().length : 1);

  const safeAvailable = Math.max(1, available - 1);
  const autoJobs = Math.max(1, Math.min(packageCount, safeAvailable, 8));

  if (packageCount < 20) {
    return Math.min(autoJobs, 2);
  }

  return autoJobs;
}

function createAnalysisWorker(workerPath, initPayload) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(workerPath);
    let ready = false;
    let settled = false;
    let currentTask = null;

    const rejectPendingTask = (err) => {
      if (currentTask) {
        const taskReject = currentTask.reject;
        currentTask = null;
        taskReject(err);
      }
    };

    const onError = (err) => {
      if (!ready && !settled) {
        settled = true;
        reject(err);
        return;
      }
      rejectPendingTask(err);
    };

    const onExit = (code) => {
      if (!ready && !settled && code !== 0) {
        settled = true;
        reject(new Error(`Analysis worker exited with code ${code}`));
        return;
      }
      if (code !== 0) {
        rejectPendingTask(new Error(`Analysis worker exited with code ${code}`));
      }
    };

    const onMessage = (message) => {
      if (!message || typeof message !== 'object') {
        return;
      }

      if (message.type === 'ready') {
        if (settled) return;
        ready = true;
        settled = true;

        const runTask = (taskId, pkg) => {
          return new Promise((resolveTask, rejectTask) => {
            if (!ready) {
              rejectTask(new Error('Worker is not ready'));
              return;
            }
            if (currentTask) {
              rejectTask(new Error('Worker is busy'));
              return;
            }

            currentTask = { id: taskId, resolve: resolveTask, reject: rejectTask };
            worker.postMessage({ type: 'analyze', id: taskId, pkg });
          });
        };

        const terminate = async () => {
          try {
            await worker.terminate();
          } catch {
            // Ignore termination races (worker may already be gone).
          }
        };

        resolve({ runTask, terminate });
        return;
      }

      if (message.type === 'init_error' && !ready && !settled) {
        settled = true;
        const err = new Error(message.error?.message || 'Failed to initialize analysis worker');
        if (message.error?.stack) {
          err.stack = message.error.stack;
        }
        reject(err);
        return;
      }

      if (message.type === 'result' && currentTask && message.id === currentTask.id) {
        const taskResolve = currentTask.resolve;
        currentTask = null;
        taskResolve(Array.isArray(message.issues) ? message.issues : []);
        return;
      }

      if (message.type === 'task_error' && currentTask && message.id === currentTask.id) {
        const taskReject = currentTask.reject;
        currentTask = null;
        const err = new Error(message.error?.message || 'Worker task failed');
        if (message.error?.stack) {
          err.stack = message.error.stack;
        }
        taskReject(err);
      }
    };

    worker.on('message', onMessage);
    worker.on('error', onError);
    worker.on('exit', onExit);
    worker.postMessage({ type: 'init', ...initPayload });
  });
}

async function collectIssuesWithWorkers(packages, lockIndex, analysisConfig, ignoredPackageMatchers, workerJobs) {
  const workerCount = Math.min(workerJobs, packages.length);
  if (workerCount <= 1) {
    return collectIssuesSequential(packages, lockIndex, analysisConfig, ignoredPackageMatchers);
  }

  const workerPath = path.join(__dirname, 'analysis-worker.js');
  const initPayload = {
    lockIndex: serializeLockIndex(lockIndex),
    config: analysisConfig,
  };
  const workers = await Promise.all(
    Array.from({ length: workerCount }, () => createAnalysisWorker(workerPath, initPayload))
  );

  const pkgIssuesByIndex = new Array(packages.length);
  let nextIndex = 0;

  const workerLoop = async (workerClient) => {
    while (true) {
      const currentIndex = nextIndex;
      nextIndex += 1;

      if (currentIndex >= packages.length) {
        break;
      }

      const pkg = packages[currentIndex];
      if (matchesAnyCompiledGlob(ignoredPackageMatchers, pkg.name)) {
        pkgIssuesByIndex[currentIndex] = [];
        continue;
      }

      pkgIssuesByIndex[currentIndex] = await workerClient.runTask(currentIndex, pkg);
    }
  };

  try {
    await Promise.all(workers.map(workerLoop));
  } finally {
    await Promise.allSettled(workers.map(worker => worker.terminate()));
  }

  return flattenAnalyzedIssues(packages, pkgIssuesByIndex, analysisConfig.ignoredRules);
}

function prepareRun(argv = process.argv) {
  const args = parseArgs(argv);

  if (args.help) {
    printHelp();
    return { done: true, result: { exitCode: 0 } };
  }

  if (args.showVersion) {
    console.log(pkgMeta.version || 'unknown');
    return { done: true, result: { exitCode: 0 } };
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
      console.log(color('  analysisJobs', colors.cyan), '      - Worker threads for scanCode (0 = auto)');
      console.log(color('  detailed', colors.cyan), '          - Show detailed analysis (verbose is alias)');
      return { done: true, result: { exitCode: 0 } };
    } else {
      if (result.exists) {
        console.log(color('⚠', colors.yellow), result.message);
      } else {
        console.error(color('✗', colors.red), result.message);
      }
      return { done: true, result: { exitCode: result.exists ? 0 : 1 } };
    }
  }

  // Load and merge configuration
  if (args.configPath && !fs.existsSync(args.configPath)) {
    throw new Error(`Config file or directory not found: ${args.configPath}`);
  }

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
  const scanRoot = path.dirname(config.nodeModules);
  const resolvedLock = config.lockPath || detectDefaultLockfile([scanRoot, process.cwd()]);
  const lockIndex = buildLockIndex(resolvedLock);

  const packages = collectPackages(config.nodeModules, config.maxNestedDepth);
  const ignoredPackageMatchers = compileGlobMatchers(config.ignoredPackages);
  const analysisConfig = createAnalysisConfig(config);

  return {
    done: false,
    config,
    analysisConfig,
    resolvedLock,
    lockIndex,
    packages,
    ignoredPackageMatchers,
  };
}

function buildResultAndPrint(issues, runtime) {
  const { config, resolvedLock, lockIndex, packages, analysisJobs } = runtime;

  // Filter issues by severity if --severity flag is set
  let filteredIssues = issues;
  if (config.severityFilter && config.severityFilter.length > 0) {
    const severitySet = new Set(config.severityFilter);
    filteredIssues = issues.filter(issue => severitySet.has(issue.severity));
  }

  const summary = summarize(filteredIssues);
  const overallSummary = summarize(issues);
  const context = {
    nodeModules: config.nodeModules,
    lockfile: lockIndex.lockPresent ? resolvedLock : null,
    lockfileType: lockIndex.lockType,
    packageCount: packages.length,
    failLevel: config.failOn,
    severityFilter: config.severityFilter,
    version: pkgMeta.version,
    verbose: config.verbose,
    analysisJobs,
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

  if (config.failOn && overallSummary.maxSeverity !== null && rankSeverity(overallSummary.maxSeverity) >= rankSeverity(config.failOn)) {
    return { exitCode: 1, issues, summary, analysisJobs };
  }

  return { exitCode: 0, issues, summary, analysisJobs };
}

function run(argv = process.argv) {
  const prepared = prepareRun(argv);
  if (prepared.done) {
    return prepared.result;
  }

  const issues = collectIssuesSequential(
    prepared.packages,
    prepared.lockIndex,
    prepared.analysisConfig,
    prepared.ignoredPackageMatchers
  );

  return buildResultAndPrint(issues, {
    config: prepared.config,
    resolvedLock: prepared.resolvedLock,
    lockIndex: prepared.lockIndex,
    packages: prepared.packages,
    analysisJobs: 1,
  });
}

async function runAsync(argv = process.argv) {
  const prepared = prepareRun(argv);
  if (prepared.done) {
    return prepared.result;
  }

  const jobs = resolveAnalysisJobs(prepared.analysisConfig, prepared.packages.length);
  let issues;
  let usedJobs = 1;

  if (jobs <= 1) {
    issues = collectIssuesSequential(
      prepared.packages,
      prepared.lockIndex,
      prepared.analysisConfig,
      prepared.ignoredPackageMatchers
    );
    usedJobs = 1;
  } else {
    try {
      issues = await collectIssuesWithWorkers(
        prepared.packages,
        prepared.lockIndex,
        prepared.analysisConfig,
        prepared.ignoredPackageMatchers,
        jobs
      );
      usedJobs = jobs;
    } catch (err) {
      console.warn(color(`Warning: Parallel analysis failed (${err.message}), falling back to sequential mode.`, colors.yellow));
      issues = collectIssuesSequential(
        prepared.packages,
        prepared.lockIndex,
        prepared.analysisConfig,
        prepared.ignoredPackageMatchers
      );
      usedJobs = 1;
    }
  }

  return buildResultAndPrint(issues, {
    config: prepared.config,
    resolvedLock: prepared.resolvedLock,
    lockIndex: prepared.lockIndex,
    packages: prepared.packages,
    analysisJobs: usedJobs,
  });
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
  --jobs <n>                 Worker threads for scanCode analysis (0 = auto)
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

${color('RULE IDS FOR --ignore-rules:', colors.bold)}
  corrupted_package_json, extraneous_package, version_mismatch,
  package_name_mismatch, suspicious_resolved_url, install_script,
  network_access_script, shell_execution, code_execution, git_operation_install,
  pipe_to_shell, potential_env_exfiltration, native_binary, executable_files,
  potential_typosquat, suspicious_name_pattern, no_repository, minimal_metadata,
  eval_usage, child_process_usage, sensitive_path_access, node_network_access,
  env_with_network, obfuscated_code

${color('SCAN OPTIONS:', colors.bold)}
  --max-file-size <bytes>    Max file size to scan (default: 1048576 = 1MB)
  --max-depth <n>            Max nested node_modules depth (default: 10)
  --max-files <n>            Max JS files to scan per package (0 = unlimited)
  --jobs <n>                 Number of worker threads for package analysis (0 = auto)
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

  # Parallel deep scan (auto worker count)
  chain-audit --scan-code --jobs 0

  # Detailed analysis with code snippets and evidence
  chain-audit --detailed --scan-code

${color('CONFIGURATION:', colors.bold)}
  Create a config file in your project root:
  (.chainauditrc.json, .chainauditrc, or chainaudit.config.json)
  
  Example (simplified):
  {
    "ignoredPackages": ["@types/*"],
    "ignoredRules": ["native_binary"],
    "trustedPackages": ["my-native-addon"],
    "scanCode": true,
    "verbose": true,
    "failOn": "high",
    "verifyIntegrity": false,
    "analysisJobs": 0,
    "maxFilesPerPackage": 0,
    "format": "text"
  }
  
  For full config with all options, use: ${color('chain-audit --init', colors.cyan)}

${color('DISCLAIMER:', colors.bold)}
  Licensed under MIT License, provided "AS IS" without warranty.
  The author makes no guarantees and takes no responsibility for false
  positives, false negatives, missed attacks, or any damages resulting
  from use of this tool. Use at your own risk. Always review findings
  manually and use as part of defense-in-depth.

${color('MORE INFO:', colors.bold)}
  https://github.com/HubertKasperek/chain-audit
`;
  console.log(text);
}

// Main execution
if (require.main === module) {
  runAsync()
    .then(({ exitCode }) => {
      process.exit(exitCode);
    })
    .catch((err) => {
      console.error(color(`Error: ${err.message}`, colors.red));
      if (process.env.DEBUG) {
        console.error(err.stack);
      }
      process.exit(1);
    });
}

// Export for programmatic use and testing
module.exports = { run, runAsync, summarize };
