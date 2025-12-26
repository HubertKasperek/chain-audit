'use strict';

const { color, colors } = require('./utils');

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

/**
 * Get color code for severity level
 */
function colorSeverity(severity) {
  switch (severity) {
    case 'critical':
      return color(severity.toUpperCase(), colors.magenta + colors.bold);
    case 'high':
      return color(severity.toUpperCase(), colors.red);
    case 'medium':
      return color(severity.toUpperCase(), colors.yellow);
    case 'low':
      return color(severity.toUpperCase(), colors.cyan);
    default:
      return color(severity.toUpperCase(), colors.dim);
  }
}

/**
 * Rank severity for sorting
 */
function rankSeverity(level) {
  const idx = SEVERITY_ORDER.indexOf(level);
  return idx === -1 ? -1 : idx;
}

/**
 * Format issues as human-readable text
 */
function formatText(issues, summary, context) {
  const lines = [];

  // Header
  const header = [
    color('chain-audit', colors.bold),
    context.version ? color(`v${context.version}`, colors.dim) : null,
  ].filter(Boolean).join(' ');
  
  lines.push(header);
  lines.push(color('─'.repeat(60), colors.dim));
  lines.push('');

  // Context info
  lines.push(`${color('node_modules:', colors.dim)} ${context.nodeModules}`);
  lines.push(`${color('lockfile:', colors.dim)} ${context.lockfile || 'not found (lockfile checks skipped)'}`);
  if (context.lockfileType) {
    lines.push(`${color('lockfile type:', colors.dim)} ${context.lockfileType}`);
  }
  lines.push(`${color('packages scanned:', colors.dim)} ${context.packageCount}`);
  if (context.severityFilter) {
    lines.push(`${color('severity filter:', colors.dim)} ${context.severityFilter.join(', ')}`);
  }
  if (context.failLevel) {
    lines.push(`${color('fail threshold:', colors.dim)} ${context.failLevel}`);
  }
  lines.push('');

  // Issues
  if (issues.length === 0) {
    lines.push(color('✓ No issues detected', colors.green + colors.bold));
  } else {
    lines.push(color(`Found ${issues.length} potential issue(s):`, colors.bold));
    lines.push('');

    // Sort by severity (highest first), then by package name
    const sorted = [...issues].sort((a, b) => {
      const severityDiff = rankSeverity(b.severity) - rankSeverity(a.severity);
      if (severityDiff !== 0) return severityDiff;
      return a.package.localeCompare(b.package);
    });

    // Group by severity for better readability
    let currentSeverity = null;
    for (const issue of sorted) {
      if (issue.severity !== currentSeverity) {
        currentSeverity = issue.severity;
        lines.push(color(`── ${currentSeverity.toUpperCase()} ──`, getSeverityColor(issue.severity)));
      }

      const pkgInfo = `${issue.package}@${issue.version}`;
      lines.push(`  ${color('●', getSeverityColor(issue.severity))} ${color(pkgInfo, colors.bold)}`);
      lines.push(`    ${color('reason:', colors.dim)} ${issue.reason}`);
      lines.push(`    ${color('detail:', colors.dim)} ${issue.detail}`);
      if (issue.recommendation) {
        lines.push(`    ${color('fix:', colors.dim)} ${issue.recommendation}`);
      }
      lines.push('');
    }
  }

  // Summary
  lines.push(color('─'.repeat(60), colors.dim));
  lines.push(color('Summary:', colors.bold));
  
  // When severity filter is active, only show filtered levels in the order specified
  const levelsToShow = context.severityFilter && context.severityFilter.length > 0
    ? context.severityFilter
    : SEVERITY_ORDER;
  
  const summaryParts = levelsToShow.map(level => {
    const count = summary.counts[level] || 0;
    if (count === 0) return `${level}: ${color('0', colors.dim)}`;
    return `${level}: ${color(String(count), getSeverityColor(level))}`;
  });
  lines.push('  ' + summaryParts.join(' │ '));

  if (issues.length > 0) {
    lines.push('');
    lines.push(`${color('Max severity:', colors.dim)} ${colorSeverity(summary.maxSeverity)}`);
  }

  // Footer with author and license
  lines.push('');
  lines.push(color('─'.repeat(60), colors.dim));
  lines.push(color('chain-audit by Hubert Kasperek • MIT License', colors.dim));

  return lines.join('\n');
}

/**
 * Get ANSI color code for severity
 */
function getSeverityColor(severity) {
  switch (severity) {
    case 'critical': return colors.magenta;
    case 'high': return colors.red;
    case 'medium': return colors.yellow;
    case 'low': return colors.cyan;
    default: return colors.dim;
  }
}

/**
 * Format issues as JSON
 */
function formatJson(issues, summary, context) {
  // When severity filter is active, only include filtered levels in summary counts
  let summaryCounts;
  if (context.severityFilter && context.severityFilter.length > 0) {
    summaryCounts = {};
    for (const level of context.severityFilter) {
      summaryCounts[level] = summary.counts[level] || 0;
    }
  } else {
    summaryCounts = summary.counts;
  }

  const payload = {
    version: context.version || null,
    timestamp: new Date().toISOString(),
    issues: issues.map(issue => ({
      severity: issue.severity,
      reason: issue.reason,
      detail: issue.detail,
      recommendation: issue.recommendation || null,
      package: issue.package,
      version: issue.version,
      path: issue.path,
    })),
    summary: {
      ...summaryCounts,
      total: issues.length,
      maxSeverity: summary.maxSeverity,
    },
    context: {
      nodeModules: context.nodeModules,
      lockfile: context.lockfile,
      lockfileType: context.lockfileType || null,
      packageCount: context.packageCount,
      severityFilter: context.severityFilter || null,
      failLevel: context.failLevel,
    },
  };

  return JSON.stringify(payload, null, 2);
}

/**
 * Format issues as SARIF (Static Analysis Results Interchange Format)
 * Compatible with GitHub Code Scanning
 */
function formatSarif(issues, summary, context) {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'chain-audit',
            version: context.version || '1.0.0',
            informationUri: 'https://github.com/hukasx0/chain-audit',
            rules: generateSarifRules(),
          },
        },
        results: issues.map((issue, index) => ({
          ruleId: issue.reason,
          level: mapSeverityToSarif(issue.severity),
          message: {
            text: `${issue.detail}${issue.recommendation ? `\n\nRecommendation: ${issue.recommendation}` : ''}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: `node_modules/${issue.path}/package.json`,
                  uriBaseId: '%SRCROOT%',
                },
              },
              logicalLocations: [
                {
                  name: issue.package,
                  kind: 'module',
                  fullyQualifiedName: `${issue.package}@${issue.version}`,
                },
              ],
            },
          ],
          partialFingerprints: {
            primaryLocationLineHash: Buffer.from(`${issue.package}:${issue.reason}:${index}`).toString('base64'),
          },
        })),
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: new Date().toISOString(),
          },
        ],
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

/**
 * Generate SARIF rule definitions
 */
function generateSarifRules() {
  return [
    {
      id: 'extraneous_package',
      name: 'ExtraneousPackage',
      shortDescription: { text: 'Package not in lockfile' },
      fullDescription: { text: 'A package exists in node_modules but is not listed in the lockfile' },
      helpUri: 'https://docs.npmjs.com/cli/v8/commands/npm-ci',
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'version_mismatch',
      name: 'VersionMismatch',
      shortDescription: { text: 'Version differs from lockfile' },
      fullDescription: { text: 'The installed package version does not match the lockfile' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'install_script',
      name: 'InstallScript',
      shortDescription: { text: 'Has install lifecycle script' },
      fullDescription: { text: 'Package has preinstall, install, postinstall, or prepare script' },
      defaultConfiguration: { level: 'warning' },
    },
    {
      id: 'network_access_script',
      name: 'NetworkAccessScript',
      shortDescription: { text: 'Script contains network access' },
      fullDescription: { text: 'A script contains patterns suggesting network access (curl, wget, etc.)' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'shell_execution',
      name: 'ShellExecution',
      shortDescription: { text: 'Script executes shell commands' },
      fullDescription: { text: 'A script executes shell commands (bash -c, sh -c, etc.)' },
      defaultConfiguration: { level: 'warning' },
    },
    {
      id: 'code_execution',
      name: 'CodeExecution',
      shortDescription: { text: 'Dynamic code execution' },
      fullDescription: { text: 'Script contains dynamic code execution (node -e, python -c, etc.)' },
      defaultConfiguration: { level: 'warning' },
    },
    {
      id: 'pipe_to_shell',
      name: 'PipeToShell',
      shortDescription: { text: 'Pipes content to shell' },
      fullDescription: { text: 'Script pipes downloaded content directly to shell execution' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'potential_env_exfiltration',
      name: 'PotentialEnvExfiltration',
      shortDescription: { text: 'Possible environment variable exfiltration' },
      fullDescription: { text: 'Script accesses environment variables and has network capabilities' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'native_binary',
      name: 'NativeBinary',
      shortDescription: { text: 'Contains native binaries' },
      fullDescription: { text: 'Package contains native binary files (.node, .so, .dll, .dylib)' },
      defaultConfiguration: { level: 'note' },
    },
    {
      id: 'potential_typosquat',
      name: 'PotentialTyposquat',
      shortDescription: { text: 'Possible typosquatting' },
      fullDescription: { text: 'Package name is very similar to a popular package' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'suspicious_name_pattern',
      name: 'SuspiciousNamePattern',
      shortDescription: { text: 'Suspicious package name' },
      fullDescription: { text: 'Package name follows patterns commonly used in typosquatting' },
      defaultConfiguration: { level: 'warning' },
    },
    {
      id: 'eval_usage',
      name: 'EvalUsage',
      shortDescription: { text: 'Uses eval() or similar' },
      fullDescription: { text: 'Code uses eval(), new Function(), or similar dynamic code execution' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'child_process_usage',
      name: 'ChildProcessUsage',
      shortDescription: { text: 'Uses child_process' },
      fullDescription: { text: 'Code uses child_process module to execute system commands' },
      defaultConfiguration: { level: 'warning' },
    },
    {
      id: 'sensitive_path_access',
      name: 'SensitivePathAccess',
      shortDescription: { text: 'Accesses sensitive paths' },
      fullDescription: { text: 'Code accesses sensitive file paths like ~/.ssh or ~/.aws' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'env_with_network',
      name: 'EnvWithNetwork',
      shortDescription: { text: 'Env access with network capability' },
      fullDescription: { text: 'Code accesses environment variables and has network/exec capabilities' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'obfuscated_code',
      name: 'ObfuscatedCode',
      shortDescription: { text: 'Obfuscated code detected' },
      fullDescription: { text: 'Code appears to be obfuscated (base64, hex encoding, etc.)' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'no_repository',
      name: 'NoRepository',
      shortDescription: { text: 'No repository URL' },
      fullDescription: { text: 'Package has install scripts but no repository URL in package.json' },
      defaultConfiguration: { level: 'note' },
    },
    {
      id: 'minimal_metadata',
      name: 'MinimalMetadata',
      shortDescription: { text: 'Minimal package metadata' },
      fullDescription: { text: 'Package has very little metadata (description, etc.)' },
      defaultConfiguration: { level: 'note' },
    },
    {
      id: 'git_operation_install',
      name: 'GitOperationInstall',
      shortDescription: { text: 'Git operations in install script' },
      fullDescription: { text: 'Install script performs git operations' },
      defaultConfiguration: { level: 'warning' },
    },
    {
      id: 'node_network_access',
      name: 'NodeNetworkAccess',
      shortDescription: { text: 'Node.js network API usage' },
      fullDescription: { text: 'Code uses Node.js network APIs (fetch, https, axios, etc.)' },
      defaultConfiguration: { level: 'warning' },
    },
  ];
}

/**
 * Map our severity levels to SARIF levels
 */
function mapSeverityToSarif(severity) {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
    default:
      return 'note';
  }
}

module.exports = {
  formatText,
  formatJson,
  formatSarif,
};
