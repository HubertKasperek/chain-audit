'use strict';

const { color, colors } = require('./utils');

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

/**
 * Get color code for severity level
 */
function colorSeverity(severity) {
  if (severity === null) {
    return color('none', colors.dim);
  }
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
  lines.push(color('Zero-dependency heuristic scanner CLI to detect supply chain attacks in node_modules', colors.dim));
  lines.push(color('─'.repeat(60), colors.dim));
  lines.push('');

  // Context info
  lines.push(`${color('node_modules:', colors.dim)} ${context.nodeModules}`);
  lines.push(`${color('lockfile:', colors.dim)} ${context.lockfile || 'not found (lockfile checks skipped)'}`);
  if (context.lockfileType) {
    lines.push(`${color('lockfile type:', colors.dim)} ${context.lockfileType}`);
  }
  lines.push(`${color('packages scanned:', colors.dim)} ${context.packageCount}`);
  lines.push(`${color('analysis workers:', colors.dim)} ${context.analysisJobs || 1}`);
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
        const severityLabel = currentSeverity ? currentSeverity.toUpperCase() : 'UNKNOWN';
        lines.push(color(`── ${severityLabel} ──`, getSeverityColor(issue.severity)));
      }

      const pkgInfo = `${issue.package}@${issue.version}`;
      lines.push(`  ${color('●', getSeverityColor(issue.severity))} ${color(pkgInfo, colors.bold)}`);
      const dependencyTreePath = formatDependencyTreePath(issue.path);
      if (dependencyTreePath) {
        lines.push(`    ${color('dependency tree:', colors.dim)} ${dependencyTreePath}`);
      }
      lines.push(`    ${color('reason:', colors.dim)} ${issue.reason}`);
      lines.push(`    ${color('detail:', colors.dim)} ${issue.detail}`);
      if (issue.recommendation) {
        lines.push(`    ${color('fix:', colors.dim)} ${issue.recommendation}`);
      }
      
      // Verbose information
      if (issue.verbose && context.verbose) {
        lines.push('');
        lines.push(`    ${color('═══ DETAILED ANALYSIS ═══', colors.cyan + colors.bold)}`);
        
        // Package metadata
        if (issue.verbose.packageMetadata) {
          const meta = issue.verbose.packageMetadata;
          lines.push(`    ${color('Package Info:', colors.bold)}`);
          if (meta.author) lines.push(`      ${color('author:', colors.dim)} ${meta.author}`);
          if (meta.repository) lines.push(`      ${color('repository:', colors.dim)} ${meta.repository}`);
          if (meta.license) lines.push(`      ${color('license:', colors.dim)} ${meta.license}`);
          if (meta.homepage) lines.push(`      ${color('homepage:', colors.dim)} ${meta.homepage}`);
          if (meta.fullPath) lines.push(`      ${color('path:', colors.dim)} ${meta.fullPath}`);
        }
        
        // Trust indicators
        if (issue.verbose.trustIndicators) {
          const trust = issue.verbose.trustIndicators;
          const trustColor = trust.trustLevel === 'high' ? colors.green : 
                            trust.trustLevel === 'medium' ? colors.yellow : colors.red;
          lines.push(`    ${color('Trust Assessment:', colors.bold)}`);
          lines.push(`      ${color('trust score:', colors.dim)} ${color(`${trust.trustScore}/100 (${trust.trustLevel})`, trustColor)}`);
          if (trust.trustedScope) lines.push(`      ${color('✓', colors.green)} Trusted scope: ${trust.scope}`);
          if (trust.hasRepository) lines.push(`      ${color('✓', colors.green)} Has repository`);
          else lines.push(`      ${color('✗', colors.red)} No repository`);
          if (trust.knownLegitimate) lines.push(`      ${color('✓', colors.green)} Known legitimate package`);
        }
        
        // Evidence
        if (issue.verbose.evidence) {
          lines.push(`    ${color('Evidence:', colors.bold)}`);
          const evidence = issue.verbose.evidence;
          for (const [key, value] of Object.entries(evidence)) {
            if (value === null || value === undefined) continue;
            if (typeof value === 'object' && !Array.isArray(value)) {
              lines.push(`      ${color(key + ':', colors.dim)}`);
              for (const [k, v] of Object.entries(value)) {
                lines.push(`        ${color(k + ':', colors.dim)} ${formatValue(v)}`);
              }
            } else if (Array.isArray(value) && value.length > 0) {
              lines.push(`      ${color(key + ':', colors.dim)}`);
              for (const item of value.slice(0, 5)) {
                if (typeof item === 'object') {
                  const itemStr = Object.entries(item)
                    .filter(([, v]) => v !== null && v !== undefined)
                    .map(([k, v]) => `${k}: ${formatValue(v)}`)
                    .join(', ');
                  lines.push(`        - ${itemStr}`);
                } else {
                  lines.push(`        - ${formatValue(item)}`);
                }
              }
              if (value.length > 5) {
                lines.push(`        ${color(`... and ${value.length - 5} more`, colors.dim)}`);
              }
            } else {
              lines.push(`      ${color(key + ':', colors.dim)} ${formatValue(value)}`);
            }
          }
        }
        
        // Code snippet
        if (issue.verbose.codeSnippet) {
          lines.push(`    ${color('Code Snippet:', colors.bold)}`);
          const snippetLines = issue.verbose.codeSnippet.split('\n');
          const isMinified = issue.verbose.isMinified;
          
          for (const snippetLine of snippetLines) {
            const isHighlighted = snippetLine.startsWith('>>>');
            const isNote = snippetLine.includes('[Minified code') || 
                          snippetLine.includes('Note:') || 
                          snippetLine.includes('column') ||
                          snippetLine.includes('match at');
            
            if (isNote) {
              // Style notes differently - use cyan for informational notes
              lines.push(`      ${color(snippetLine, colors.cyan + colors.dim)}`);
            } else if (isHighlighted) {
              lines.push(`      ${color(snippetLine, colors.yellow)}`);
            } else {
              lines.push(`      ${color(snippetLine, colors.dim)}`);
            }
          }
          
          if (issue.verbose.lineNumber && !isMinified) {
            lines.push(`      ${color(`↑ Line ${issue.verbose.lineNumber}`, colors.cyan)}`);
          }
        }
        
        // Environment code snippet (for env_with_network)
        if (issue.verbose.envCodeSnippet) {
          lines.push(`    ${color('Environment Access:', colors.bold)}`);
          const snippetLines = issue.verbose.envCodeSnippet.split('\n');
          const isMinified = issue.verbose.envIsMinified || false;
          
          for (const snippetLine of snippetLines) {
            const isHighlighted = snippetLine.startsWith('>>>');
            const isNote = snippetLine.includes('[Minified code') || 
                          snippetLine.includes('Note:') || 
                          snippetLine.includes('column') ||
                          snippetLine.includes('match at');
            
            if (isNote) {
              lines.push(`      ${color(snippetLine, colors.cyan + colors.dim)}`);
            } else if (isHighlighted) {
              lines.push(`      ${color(snippetLine, colors.yellow)}`);
            } else {
              lines.push(`      ${color(snippetLine, colors.dim)}`);
            }
          }
          
          if (issue.verbose.envLineNumber && !isMinified) {
            lines.push(`      ${color(`↑ Line ${issue.verbose.envLineNumber}`, colors.cyan)}`);
          }
        }
        
        if (issue.verbose.networkCodeSnippet) {
          // For env_with_network, this could be network OR exec capability
          const accessType = issue.reason === 'env_with_network' ? 'Network/Exec Access' : 'Network Access';
          lines.push(`    ${color(`${accessType}:`, colors.bold)}`);
          const snippetLines = issue.verbose.networkCodeSnippet.split('\n');
          const isMinified = issue.verbose.networkIsMinified || false;
          
          for (const snippetLine of snippetLines) {
            const isHighlighted = snippetLine.startsWith('>>>');
            const isNote = snippetLine.includes('[Minified code') || 
                          snippetLine.includes('Note:') || 
                          snippetLine.includes('column') ||
                          snippetLine.includes('match at');
            
            if (isNote) {
              lines.push(`      ${color(snippetLine, colors.cyan + colors.dim)}`);
            } else if (isHighlighted) {
              lines.push(`      ${color(snippetLine, colors.yellow)}`);
            } else {
              lines.push(`      ${color(snippetLine, colors.dim)}`);
            }
          }
          
          if (issue.verbose.networkLineNumber && !isMinified) {
            lines.push(`      ${color(`↑ Line ${issue.verbose.networkLineNumber}`, colors.cyan)}`);
          }
        }
        
        // Full script (for install scripts)
        if (issue.verbose.fullScript && issue.verbose.fullScript.length < 500) {
          lines.push(`    ${color('Full Script:', colors.bold)}`);
          lines.push(`      ${color(issue.verbose.fullScript, colors.dim)}`);
        }
        
        // Risk assessment
        if (issue.verbose.riskAssessment) {
          lines.push(`    ${color('Risk Assessment:', colors.bold)} ${color(issue.verbose.riskAssessment, colors.red)}`);
        }
        
        // Verification steps
        if (issue.verbose.verificationSteps) {
          lines.push(`    ${color('Verification Steps:', colors.bold)}`);
          for (const step of issue.verbose.verificationSteps) {
            lines.push(`      ${color(step, colors.dim)}`);
          }
        }
        
        // False positive hints
        if (issue.verbose.falsePositiveHints && issue.verbose.falsePositiveHints.length > 0) {
          lines.push(`    ${color('False Positive Analysis:', colors.bold)}`);
          for (const hint of issue.verbose.falsePositiveHints) {
            const hintColor = hint.startsWith('✓') ? colors.green : 
                             hint.startsWith('⚠') ? colors.yellow : colors.dim;
            lines.push(`      ${color('•', colors.cyan)} ${color(hint, hintColor)}`);
          }
        }
        
        lines.push(`    ${color('═'.repeat(25), colors.cyan)}`);
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
  lines.push(color('https://github.com/HubertKasperek/chain-audit', colors.dim));
  lines.push('');
  lines.push(color('Disclaimer: Licensed under MIT License, provided "AS IS" without warranty.', colors.dim));
  lines.push(color('The author makes no guarantees and takes no responsibility for false', colors.dim));
  lines.push(color('positives, false negatives, missed attacks, or any damages resulting from use.', colors.dim));
  lines.push(color('Review all findings manually. Use at your own risk.', colors.dim));

  return lines.join('\n');
}

/**
 * Get ANSI color code for severity
 */
function getSeverityColor(severity) {
  if (severity === null || severity === undefined) {
    return colors.dim;
  }
  switch (severity) {
    case 'critical': return colors.magenta;
    case 'high': return colors.red;
    case 'medium': return colors.yellow;
    case 'low': return colors.cyan;
    default: return colors.dim;
  }
}

/**
 * Convert internal node_modules-relative path to human-readable dependency tree.
 * Example: "@scope/a/node_modules/b" -> "@scope/a > b"
 */
function formatDependencyTreePath(pathValue) {
  if (typeof pathValue !== 'string' || pathValue.length === 0) {
    return null;
  }

  const normalized = pathValue.replace(/\\/g, '/');
  const segments = normalized.split('/node_modules/').filter(Boolean);

  if (segments.length === 0) {
    return normalized;
  }

  return segments.join(' > ');
}

/**
 * Format a value for display, truncating long strings
 */
function formatValue(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'yes' : 'no';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') {
    if (value.length > 80) {
      return value.slice(0, 77) + '...';
    }
    return value;
  }
  if (Array.isArray(value)) {
    return `[${value.length} items]`;
  }
  return JSON.stringify(value);
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
    issues: issues.map(issue => {
      const baseIssue = {
        severity: issue.severity,
        reason: issue.reason,
        detail: issue.detail,
        recommendation: issue.recommendation || null,
        package: issue.package,
        version: issue.version,
        path: issue.path,
      };
      
      // Include verbose data in JSON if verbose mode is enabled
      if (context.verbose && issue.verbose) {
        baseIssue.verbose = issue.verbose;
      }
      
      return baseIssue;
    }),
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
      analysisJobs: context.analysisJobs || 1,
      severityFilter: context.severityFilter || null,
      failLevel: context.failLevel,
      verbose: context.verbose || false,
    },
  };

  return JSON.stringify(payload, null, 2);
}

/**
 * Format issues as SARIF (Static Analysis Results Interchange Format)
 * Compatible with GitHub Code Scanning
 * 
 * @experimental This format is experimental and may change in future versions
 */
function formatSarif(issues, summary, context) {
  const sarif = {
    $schema: 'http://json.schemastore.org/sarif-2.1.0',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'chain-audit',
            version: context.version || '1.0.0',
            informationUri: 'https://github.com/HubertKasperek/chain-audit',
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
      fullDescription: { text: 'A package exists in node_modules but is not listed in the lockfile. Often a false positive when lockfile is not synced.' },
      helpUri: 'https://docs.npmjs.com/cli/v8/commands/npm-ci',
      defaultConfiguration: { level: 'warning' },
    },
    {
      id: 'version_mismatch',
      name: 'VersionMismatch',
      shortDescription: { text: 'Version differs from lockfile' },
      fullDescription: { text: 'The installed package version does not match the lockfile' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'package_name_mismatch',
      name: 'PackageNameMismatch',
      shortDescription: { text: 'Package name does not match expected' },
      fullDescription: { text: 'Package at path has different name than expected from directory' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'suspicious_resolved_url',
      name: 'SuspiciousResolvedUrl',
      shortDescription: { text: 'Package from suspicious URL' },
      fullDescription: { text: 'Package resolved from local file or suspicious URL' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'corrupted_package_json',
      name: 'CorruptedPackageJson',
      shortDescription: { text: 'Corrupted or malformed package.json' },
      fullDescription: { text: 'Package has a malformed package.json that cannot be parsed' },
      defaultConfiguration: { level: 'error' },
    },
    {
      id: 'install_script',
      name: 'InstallScript',
      shortDescription: { text: 'Has install lifecycle script' },
      fullDescription: { text: 'Package has preinstall, install, or postinstall script' },
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
      fullDescription: { text: 'Package contains native module binary files (.node, .so, .dylib)' },
      defaultConfiguration: { level: 'note' },
    },
    {
      id: 'executable_files',
      name: 'ExecutableFiles',
      shortDescription: { text: 'Contains executable files' },
      fullDescription: { text: 'Package contains executable files (shell scripts, etc.) that may indicate supply chain attacks' },
      defaultConfiguration: { level: 'warning' },
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
  if (severity === null) {
    return 'none';
  }
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
