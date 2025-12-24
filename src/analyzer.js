'use strict';

const fs = require('fs');
const path = require('path');

// ==================== Detection Patterns ====================

/**
 * Install lifecycle scripts that run automatically
 */
const INSTALL_SCRIPT_NAMES = new Set([
  'preinstall',
  'install', 
  'postinstall',
  'prepare',
  'prepack',
  'prepublish',
  'prepublishOnly',
]);

/**
 * Network/download command patterns (high risk in install scripts)
 */
const NETWORK_PATTERNS = [
  // Unix download tools
  /\bcurl\s/i,
  /\bwget\s/i,
  /\bfetch\s/i,
  // Windows
  /invoke-webrequest/i,
  /invoke-restmethod/i,
  /\bpowershell\b.*\b(iwr|irm|downloadstring|downloadfile)\b/i,
  /\bcertutil\b.*-urlcache/i,
  /\bbitsadmin\b.*\/transfer/i,
  // Network tools
  /\bnc\s+-[^l]/i, // nc but not listening mode
  /\bnetcat\b/i,
  /\bssh\s/i,
  /\bscp\s/i,
  /\bftp\s/i,
  /\btftp\s/i,
  /\brsync\s.*:/i,
];

/**
 * Shell execution patterns (medium-high risk)
 */
const SHELL_EXEC_PATTERNS = [
  /\bbash\s+-c\b/i,
  /\bsh\s+-c\b/i,
  /\bzsh\s+-c\b/i,
  /\bpowershell\s+-c/i,
  /\bcmd\s+\/c\b/i,
];

/**
 * Code execution patterns (high risk)
 */
const CODE_EXEC_PATTERNS = [
  /\bnode\s+-e\b/i,
  /\bnode\s+--eval\b/i,
  /\bpython[23]?\s+-c\b/i,
  /\bruby\s+-e\b/i,
  /\bperl\s+-e\b/i,
];

/**
 * Dangerous eval-like patterns in JS code
 */
const EVAL_PATTERNS = [
  /\beval\s*\(/,
  /\bnew\s+Function\s*\(/,
  /\bFunction\s*\(/,
  /\bsetTimeout\s*\(\s*['"`]/,
  /\bsetInterval\s*\(\s*['"`]/,
  /\bvm\.runInContext\s*\(/,
  /\bvm\.runInNewContext\s*\(/,
  /\bvm\.runInThisContext\s*\(/,
  /\bvm\.compileFunction\s*\(/,
];

/**
 * Child process execution patterns
 */
const CHILD_PROCESS_PATTERNS = [
  /child_process/,
  /\bexec\s*\(/,
  /\bexecSync\s*\(/,
  /\bexecFile\s*\(/,
  /\bexecFileSync\s*\(/,
  /\bspawn\s*\(/,
  /\bspawnSync\s*\(/,
  /\bfork\s*\(/,
];

/**
 * Node.js network/HTTP patterns (for code scanning)
 * These are used for data exfiltration in attacks like Shai-Hulud 2.0
 */
const NODE_NETWORK_PATTERNS = [
  /\bfetch\s*\(/,
  /\brequire\s*\(\s*['"`]https?['"`]\s*\)/,
  /\bfrom\s+['"`]https?['"`]/,
  /\bhttps?\.request\s*\(/,
  /\bhttps?\.get\s*\(/,
  /\baxios\s*[.(]/,
  /\bgot\s*[.(]/,
  /\bnode-fetch/,
  /\bundici/,
  /\bky\s*[.(]/,
  /\bsuperagent/,
  /\brequest\s*\(/,
  // WebSocket for C2 communication
  /\bWebSocket\s*\(/,
  /\bws\s*[.(]/,
  // DNS exfiltration
  /\bdns\.resolve/,
  /\bdns\.lookup/,
];

/**
 * Environment variable access patterns (potential credential stealing)
 */
const ENV_ACCESS_PATTERNS = [
  /process\.env\s*\[/,
  /process\.env\./,
  // Specific sensitive env vars
  /\b(AWS_SECRET|AWS_ACCESS|GITHUB_TOKEN|NPM_TOKEN|API_KEY|SECRET_KEY|PRIVATE_KEY|PASSWORD|CREDENTIALS?)\b/i,
];

/**
 * File system access to sensitive locations
 */
const SENSITIVE_PATH_PATTERNS = [
  /['"~]\/\.ssh/,
  /['"~]\/\.aws/,
  /['"~]\/\.npmrc/,
  /['"~]\/\.gitconfig/,
  /['"~]\/\.gnupg/,
  /['"~]\/\.config/,
  /['"~]\/\.kube/,
  /['"~]\/\.docker/,
  /\/etc\/passwd/,
  /\/etc\/shadow/,
  /\/etc\/hosts/,
];

/**
 * Obfuscation indicators
 */
const OBFUSCATION_PATTERNS = [
  // Long base64-like strings
  /['"`][A-Za-z0-9+/=]{100,}['"`]/,
  // Hex-encoded strings
  /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/,
  // Unicode escape sequences
  /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){10,}/,
  // Array of char codes
  /String\.fromCharCode\([^)]{50,}\)/,
  // Heavily chained array methods (obfuscators love these)
  /\]\s*\[\s*['"`]\w+['"`]\s*\]\s*\[\s*['"`]\w+['"`]\s*\]/,
];

/**
 * Native binary extensions
 */
const NATIVE_EXTENSIONS = ['.node', '.so', '.dll', '.dylib', '.exe'];

/**
 * Git/version control patterns (lower risk but worth noting)
 */
const GIT_PATTERNS = [
  /\bgit\s+clone\b/i,
  /\bgit\s+fetch\b/i,
  /\bgit\s+pull\b/i,
  /\bgh\s+/i,
];

/**
 * Common typosquatting targets
 */
const POPULAR_PACKAGES = [
  'lodash', 'express', 'react', 'axios', 'moment', 'request', 'async',
  'chalk', 'commander', 'debug', 'inquirer', 'yargs', 'glob', 'mkdirp',
  'underscore', 'webpack', 'babel', 'eslint', 'typescript', 'jest',
  'mocha', 'prettier', 'vue', 'angular', 'jquery', 'bootstrap',
  'socket.io', 'mongoose', 'sequelize', 'passport', 'dotenv',
];

// ==================== Analysis Functions ====================

/**
 * Analyze a package for potential supply chain risks
 * @param {Object} pkg - Package object from collector
 * @param {Object} lockIndex - Lock file index
 * @param {Object} config - Configuration options
 * @returns {Object[]} Array of issues found
 */
function analyzePackage(pkg, lockIndex, config = {}) {
  const issues = [];

  // 1. Check lockfile integrity
  checkLockfileIntegrity(pkg, lockIndex, issues);

  // 2. Analyze install scripts
  analyzeScripts(pkg, config, issues);

  // 3. Check for native binaries
  checkNativeBinaries(pkg, issues);

  // 4. Check for typosquatting
  checkTyposquatting(pkg, issues);

  // 5. Check metadata anomalies
  checkMetadataAnomalies(pkg, issues);

  // 6. Optional: Deep code analysis
  if (config.scanCode) {
    analyzeCode(pkg, config, issues);
  }

  return issues;
}

/**
 * Check package integrity against lockfile
 */
function checkLockfileIntegrity(pkg, lockIndex, issues) {
  if (!lockIndex.lockPresent) return;

  const lockByPath = lockIndex.indexByPath.get(pkg.relativePath);
  const lockByName = lockIndex.indexByName.get(pkg.name);

  if (!lockByPath && !lockByName) {
    issues.push({
      severity: 'critical',
      reason: 'extraneous_package',
      detail: 'Package exists in node_modules but is missing from lockfile. This could indicate a supply chain attack or compromised node_modules.',
      recommendation: 'Run `npm ci` to reinstall from lockfile, or investigate how this package was added.',
    });
    return;
  }

  const expectedVersion = lockByPath?.version || lockByName?.version;
  if (expectedVersion && expectedVersion !== pkg.version) {
    issues.push({
      severity: 'critical', 
      reason: 'version_mismatch',
      detail: `Installed version ${pkg.version} does not match lockfile version ${expectedVersion}. Package may have been tampered with.`,
      recommendation: 'Run `npm ci` to reinstall correct version. Investigate if this was intentional.',
    });
  }
}

/**
 * Analyze package scripts for suspicious patterns
 */
function analyzeScripts(pkg, config, issues) {
  const trustedPatterns = config.trustedPatterns || {};
  const trustedPackages = config.trustedPackages || [];

  // Check if package is trusted
  const isTrusted = trustedPackages.some(pattern => {
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      return regex.test(pkg.name);
    }
    return pattern === pkg.name;
  });

  for (const [scriptName, scriptValue] of Object.entries(pkg.scripts)) {
    if (typeof scriptValue !== 'string') continue;
    
    const script = String(scriptValue);
    const isInstallLifecycle = INSTALL_SCRIPT_NAMES.has(scriptName);

    // Check for trusted patterns that reduce severity
    const hasTrustedPattern = Object.keys(trustedPatterns).some(
      pattern => script.includes(pattern)
    );

    if (isInstallLifecycle) {
      // Flag all install scripts (medium baseline)
      const baseSeverity = isTrusted ? 'info' : (hasTrustedPattern ? 'low' : 'medium');
      issues.push({
        severity: baseSeverity,
        reason: 'install_script',
        detail: `Has ${scriptName} script: ${truncate(script, 200)}`,
        recommendation: 'Review the script to ensure it performs only expected operations.',
      });

      // Check for high-risk patterns in install scripts
      analyzeScriptContent(script, scriptName, true, isTrusted, issues);
    } else {
      // Non-install scripts - still check for suspicious patterns but lower severity
      analyzeScriptContent(script, scriptName, false, isTrusted, issues);
    }
  }
}

/**
 * Analyze script content for suspicious patterns
 */
function analyzeScriptContent(script, scriptName, isInstall, isTrusted, issues) {
  // script analysis uses regex patterns directly, no need for lowercase

  // Network access
  for (const pattern of NETWORK_PATTERNS) {
    if (pattern.test(script)) {
      issues.push({
        severity: isInstall ? (isTrusted ? 'low' : 'high') : 'medium',
        reason: 'network_access_script',
        detail: `Script "${scriptName}" contains network access pattern: ${truncate(script, 150)}`,
        recommendation: 'Verify that network access is legitimate and from trusted sources.',
      });
      break;
    }
  }

  // Shell execution
  for (const pattern of SHELL_EXEC_PATTERNS) {
    if (pattern.test(script)) {
      issues.push({
        severity: isInstall ? 'high' : 'medium',
        reason: 'shell_execution',
        detail: `Script "${scriptName}" executes shell commands: ${truncate(script, 150)}`,
        recommendation: 'Review the shell commands being executed.',
      });
      break;
    }
  }

  // Code execution
  for (const pattern of CODE_EXEC_PATTERNS) {
    if (pattern.test(script)) {
      issues.push({
        severity: isInstall ? 'high' : 'medium', 
        reason: 'code_execution',
        detail: `Script "${scriptName}" executes code dynamically: ${truncate(script, 150)}`,
        recommendation: 'Investigate what code is being executed.',
      });
      break;
    }
  }

  // Git operations in install (potential for fetching malicious code)
  if (isInstall) {
    for (const pattern of GIT_PATTERNS) {
      if (pattern.test(script)) {
        issues.push({
          severity: 'medium',
          reason: 'git_operation_install',
          detail: `Script "${scriptName}" performs git operations: ${truncate(script, 150)}`,
          recommendation: 'Ensure git operations fetch from trusted repositories.',
        });
        break;
      }
    }
  }

  // Pipe to shell (extremely dangerous)
  if (/\|\s*(ba)?sh\b/i.test(script) || /\|\s*node\b/i.test(script)) {
    issues.push({
      severity: 'critical',
      reason: 'pipe_to_shell',
      detail: `Script "${scriptName}" pipes content to shell: ${truncate(script, 150)}`,
      recommendation: 'DANGER: Piping to shell is a common attack vector. Investigate immediately.',
    });
  }

  // Environment variable exfiltration patterns
  if (isInstall && /process\.env|%\w+%|\$\w+|\$\{\w+\}/.test(script)) {
    // Check for patterns that might send env vars somewhere
    if (NETWORK_PATTERNS.some(p => p.test(script))) {
      issues.push({
        severity: 'critical',
        reason: 'potential_env_exfiltration',
        detail: `Script "${scriptName}" accesses environment variables and has network access`,
        recommendation: 'This could be exfiltrating secrets. Investigate immediately.',
      });
    }
  }
}

/**
 * Check for native binary artifacts
 */
function checkNativeBinaries(pkg, issues) {
  const found = findNativeArtifacts(pkg.dir, 3);
  
  if (found.length > 0) {
    const listed = found.slice(0, 3).map(p => path.basename(p)).join(', ');
    issues.push({
      severity: 'low',
      reason: 'native_binary',
      detail: `Contains native binaries: ${listed}${found.length > 3 ? `, +${found.length - 3} more` : ''}`,
      recommendation: 'Native binaries are harder to audit. Ensure this is a known native module.',
    });
  }
}

/**
 * Find native artifact files in package
 */
function findNativeArtifacts(pkgDir, maxDepth = 3) {
  const found = [];
  const stack = [{ dir: pkgDir, depth: 0 }];

  while (stack.length > 0) {
    const { dir, depth } = stack.pop();
    if (depth > maxDepth) continue;

    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      
      if (entry.isDirectory() && !entry.name.startsWith('.')) {
        stack.push({ dir: fullPath, depth: depth + 1 });
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (NATIVE_EXTENSIONS.includes(ext)) {
          found.push(fullPath);
        }
      }
    }
  }

  return found;
}

/**
 * Trusted npm organizations/scopes (official packages, not typosquatting)
 */
const TRUSTED_SCOPES = new Set([
  '@eslint',
  '@babel',
  '@types',
  '@jest',
  '@angular',
  '@vue',
  '@react',
  '@microsoft',
  '@google',
  '@aws-sdk',
  '@swc',
  '@vercel',
  '@nestjs',
  '@prisma',
  '@emotion',
  '@chakra-ui',
  '@mui',
  '@tanstack',
  '@trpc',
  '@octokit',
  '@humanwhocodes', // ESLint ecosystem
  '@nodelib',
]);

/**
 * Known legitimate packages that might trigger false positives
 */
const KNOWN_LEGITIMATE_PACKAGES = new Set([
  'esquery',      // ESLint query language, not related to jquery
  'is-glob',      // Well-known utility
  'is-number',    // Well-known utility
  'has-flag',     // Well-known utility
  'get-stream',   // Well-known utility
  'node-fetch',   // Official fetch polyfill
  'cross-env',    // Well-known utility
  'fast-glob',    // Well-known utility
]);

/**
 * Check for potential typosquatting
 */
function checkTyposquatting(pkg, issues) {
  // Skip trusted scopes
  if (pkg.name.startsWith('@')) {
    const scope = pkg.name.split('/')[0];
    if (TRUSTED_SCOPES.has(scope)) {
      return;
    }
  }

  // Skip known legitimate packages
  if (KNOWN_LEGITIMATE_PACKAGES.has(pkg.name)) {
    return;
  }

  const pkgName = pkg.name.replace(/^@[^/]+\//, ''); // Remove scope for comparison
  
  for (const popular of POPULAR_PACKAGES) {
    if (pkgName === popular) continue;
    
    // Skip if names are too different in length
    const lengthDiff = Math.abs(pkgName.length - popular.length);
    if (lengthDiff > 3) continue;
    
    const distance = levenshteinDistance(pkgName.toLowerCase(), popular.toLowerCase());
    
    // More strict threshold for short names (less than 5 chars need exact match or 1 diff)
    const threshold = pkgName.length < 5 ? 1 : 2;
    
    // Flag if very similar
    if (distance > 0 && distance <= threshold) {
      issues.push({
        severity: 'high',
        reason: 'potential_typosquat',
        detail: `Package name "${pkg.name}" is similar to popular package "${popular}" (edit distance: ${distance})`,
        recommendation: 'Verify this is the intended package and not a typosquatting attack.',
      });
      break;
    }
  }

  // Check for common typosquatting patterns (only for unscoped packages)
  if (!pkg.name.startsWith('@')) {
    checkSuspiciousNamePatterns(pkg, pkgName, issues);
  }
}

/**
 * Check for suspicious naming patterns that might indicate typosquatting
 */
function checkSuspiciousNamePatterns(pkg, pkgName, issues) {
  const suspiciousPatterns = [
    // Prepending common words to popular package names
    { pattern: /^(get|my|the|fake|real|true|best|free|super|ultra)-?(.+)$/i, group: 2 },
    // Numbers that look like letter substitution (l00dash, r3act)
    { pattern: /[0-9]/, check: 'substitution' },
  ];

  for (const { pattern, group, check } of suspiciousPatterns) {
    if (check === 'substitution') {
      // Check for l33t speak style substitutions
      const normalized = pkgName
        .replace(/0/g, 'o')
        .replace(/1/g, 'l')
        .replace(/3/g, 'e')
        .replace(/4/g, 'a')
        .replace(/5/g, 's')
        .replace(/7/g, 't');
      
      if (normalized !== pkgName && POPULAR_PACKAGES.includes(normalized.toLowerCase())) {
        issues.push({
          severity: 'high',
          reason: 'suspicious_name_pattern',
          detail: `Package name "${pkg.name}" uses character substitution similar to "${normalized}"`,
          recommendation: 'This could be a typosquatting attempt using character substitution.',
        });
        break;
      }
    } else if (pattern.test(pkgName)) {
      const match = pkgName.match(pattern);
      if (match && match[group]) {
        const stripped = match[group].toLowerCase();
        if (POPULAR_PACKAGES.includes(stripped)) {
          issues.push({
            severity: 'medium',
            reason: 'suspicious_name_pattern',
            detail: `Package name "${pkg.name}" might be impersonating "${stripped}"`,
            recommendation: 'Verify this is the intended package.',
          });
          break;
        }
      }
    }
  }
}

/**
 * Check package metadata for anomalies
 */
function checkMetadataAnomalies(pkg, issues) {
  // Very new package with install scripts and no repository
  if (!pkg.repository && Object.keys(pkg.scripts).some(s => INSTALL_SCRIPT_NAMES.has(s))) {
    issues.push({
      severity: 'low',
      reason: 'no_repository',
      detail: 'Package has install scripts but no repository URL',
      recommendation: 'Packages without source repository are harder to audit.',
    });
  }

  // Empty or very short description with install scripts
  if ((!pkg.description || pkg.description.length < 10) && 
      Object.keys(pkg.scripts).some(s => INSTALL_SCRIPT_NAMES.has(s))) {
    issues.push({
      severity: 'info',
      reason: 'minimal_metadata',
      detail: 'Package has minimal description',
      recommendation: 'Low-quality metadata can indicate hastily published or malicious packages.',
    });
  }
}

/**
 * Deep code analysis (optional, slower)
 */
function analyzeCode(pkg, config, issues) {
  const maxFileSize = config.maxFileSizeForCodeScan || 1024 * 1024;
  const jsFiles = findJsFiles(pkg.dir, 2); // Only top 2 levels

  for (const filePath of jsFiles.slice(0, 10)) { // Limit files scanned
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > maxFileSize) continue;

      const content = fs.readFileSync(filePath, 'utf8');
      const relativePath = path.relative(pkg.dir, filePath);

      // Check for eval patterns
      for (const pattern of EVAL_PATTERNS) {
        if (pattern.test(content)) {
          issues.push({
            severity: 'high',
            reason: 'eval_usage',
            detail: `File "${relativePath}" uses eval() or similar dynamic code execution`,
            recommendation: 'eval() can execute arbitrary code and is often used in attacks.',
          });
          break;
        }
      }

      // Check for child_process
      for (const pattern of CHILD_PROCESS_PATTERNS) {
        if (pattern.test(content)) {
          issues.push({
            severity: 'medium',
            reason: 'child_process_usage',
            detail: `File "${relativePath}" uses child_process module`,
            recommendation: 'child_process can execute system commands. Verify usage is legitimate.',
          });
          break;
        }
      }

      // Check for sensitive path access
      for (const pattern of SENSITIVE_PATH_PATTERNS) {
        if (pattern.test(content)) {
          issues.push({
            severity: 'high',
            reason: 'sensitive_path_access',
            detail: `File "${relativePath}" accesses sensitive paths (${pattern.source})`,
            recommendation: 'Accessing ~/.ssh, ~/.aws, or similar paths can indicate credential theft.',
          });
          break;
        }
      }

      // Check for Node.js network patterns (like Shai-Hulud 2.0 attack)
      for (const pattern of NODE_NETWORK_PATTERNS) {
        if (pattern.test(content)) {
          issues.push({
            severity: 'medium',
            reason: 'node_network_access',
            detail: `File "${relativePath}" uses Node.js network APIs (${pattern.source})`,
            recommendation: 'Network access in dependencies should be reviewed for legitimacy.',
          });
          break;
        }
      }

      // Check for env var access (in context)
      if (ENV_ACCESS_PATTERNS.some(p => p.test(content))) {
        // Only flag if also has network patterns or child_process
        const hasShellNetwork = NETWORK_PATTERNS.some(p => p.test(content));
        const hasNodeNetwork = NODE_NETWORK_PATTERNS.some(p => p.test(content));
        const hasChildProcess = CHILD_PROCESS_PATTERNS.some(p => p.test(content));
        
        if (hasShellNetwork || hasNodeNetwork || hasChildProcess) {
          issues.push({
            severity: 'critical',
            reason: 'env_with_network',
            detail: `File "${relativePath}" accesses environment variables and has network/exec capabilities`,
            recommendation: 'DANGER: This pattern matches credential exfiltration attacks like Shai-Hulud 2.0. Investigate immediately.',
          });
        }
      }

      // Check for obfuscation
      for (const pattern of OBFUSCATION_PATTERNS) {
        if (pattern.test(content)) {
          issues.push({
            severity: 'critical',
            reason: 'obfuscated_code',
            detail: `File "${relativePath}" appears to contain obfuscated code`,
            recommendation: 'DANGER: Obfuscated code is highly suspicious. Investigate immediately.',
          });
          break;
        }
      }

    } catch {
      // Skip files that can't be read
      continue;
    }
  }
}

/**
 * Find JavaScript files in package
 */
function findJsFiles(dir, maxDepth = 2) {
  const files = [];
  const stack = [{ dir, depth: 0 }];

  while (stack.length > 0) {
    const { dir: currentDir, depth } = stack.pop();
    if (depth > maxDepth) continue;

    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      if (entry.name === 'node_modules') continue;

      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        stack.push({ dir: fullPath, depth: depth + 1 });
      } else if (entry.isFile() && /\.(js|mjs|cjs)$/.test(entry.name)) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

/**
 * Calculate Levenshtein distance between two strings
 */
function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Truncate string for display
 */
function truncate(str, maxLen) {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}

module.exports = {
  analyzePackage,
  INSTALL_SCRIPT_NAMES,
  POPULAR_PACKAGES,
};
